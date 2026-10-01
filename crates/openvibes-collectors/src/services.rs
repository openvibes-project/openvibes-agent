//! Host services (protocol P15): the host's listening sockets, servers
//! only, and its running systemd services, for the platform's asset view.
//! No facts.
//!
//! - Listeners come from `/proc/net/{tcp,tcp6,udp,udp6}` (as the `ports`
//!   collector): TCP in `LISTEN`, and unconnected UDP below the ephemeral
//!   range (`/proc/sys/net/ipv4/ip_local_port_range`), so client sockets are
//!   left out.
//! - **Owners without privilege** (the user's decision A, 2026-10-01): the
//!   kernel's `sock_diag` netlink dump gives each socket's cgroup id to any
//!   user; the cgroup id is the inode of its directory in `/sys/fs/cgroup`,
//!   whose path names the systemd unit (the deepest `*.service` in it). A
//!   listener's `program` is set only when that unit runs one program.
//!   Sockets systemd itself holds (socket activation) belong to
//!   `init.scope`, so they have no service. `owners` is `partial`: the
//!   cgroup names the service, not the exact process.
//! - **Exact owners, opt-in** (decision B, the drop-in in
//!   `docs/components/packaging.md`): with `CAP_DAC_READ_SEARCH` and
//!   `CAP_SYS_PTRACE`, the fd walk in `fds` names the process holding each
//!   listener; `owners` is `complete` when it found them all or read
//!   every process within its cap.
//! - Services are the `*.service` cgroups under `/system.slice` with at
//!   least one process: their distinct `comm`s, the process count, and the
//!   user of the lowest pid (normally the main process) from `/etc/passwd`,
//!   or the decimal uid when it has no name there (directory users).
//!
//! Without the drop-in everything read is world-readable.
//! Windows and macOS report `unsupported`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use openvibes_core::{
    CollectorError, CollectorErrorCode, HostService, Identifier, ListenerProtocol, Owners,
    SERVICE_MAX_PROGRAMS, ServiceListener,
};

use crate::ports::{Listener, Protocol, is_mapped_loopback};

/// Collector identifier reported in errors.
const SOURCE: &str = "services";

/// What one scan saw: lists in no particular order; the agent sorts and
/// cuts them to the protocol limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostServicesScan {
    /// `partial`: owners come from cgroups, not from each process's sockets.
    pub owners: Owners,
    /// Listening sockets, servers only.
    pub listeners: Vec<ServiceListener>,
    /// Running systemd services.
    pub services: Vec<HostService>,
}

/// One process of a unit.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Process {
    pub(crate) pid: u32,
    pub(crate) comm: String,
    /// Read only for the unit's main (lowest) pid.
    pub(crate) uid: Option<u32>,
}

/// What the platform layer read, joined by [`assemble`].
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Default)]
pub(crate) struct Inputs {
    pub(crate) listeners: Vec<Listener>,
    /// First port of the ephemeral range.
    pub(crate) ephemeral_start: u16,
    /// Socket inode → cgroup id; `None` when `sock_diag` failed.
    pub(crate) socket_cgroups: Option<HashMap<u64, u64>>,
    /// Cgroup id (directory inode) → its path below the cgroup root.
    pub(crate) cgroups: HashMap<u64, String>,
    /// Unit path (see [`unit_path`]) → its processes, the lowest pids
    /// first, at most a sample of them (see `process_counts`).
    pub(crate) processes: BTreeMap<String, Vec<Process>>,
    /// Unit path → how many processes it has, when more than were read.
    pub(crate) process_counts: HashMap<String, u32>,
    /// uid → user name, from `/etc/passwd`.
    pub(crate) users: HashMap<u32, String>,
    /// With the opt-in capabilities: socket inode → the `comm` and cgroup
    /// path of the process holding it.
    pub(crate) socket_owners: HashMap<u64, (String, Option<String>)>,
    /// The fd walk found every listener's holder or read every process.
    pub(crate) owners_complete: bool,
}

/// The path of the unit owning a cgroup: up to and including its deepest
/// `*.service` component (`/system.slice/system-getty.slice/getty@tty1.service`).
/// `None` for scopes, slices and the root.
#[must_use]
pub(crate) fn unit_path(cgroup: &str) -> Option<&str> {
    let end = cgroup
        .match_indices('/')
        .map(|(i, _)| i)
        .chain([cgroup.len()])
        .rev()
        .find(|&end| end > 0 && cgroup[..end].ends_with(".service"))?;
    Some(&cgroup[..end])
}

/// The unit name: the last component of a [`unit_path`].
fn unit_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A system service, not a user's (`/user.slice/…/user@1000.service/…`).
pub(crate) fn is_system(path: &str) -> bool {
    path.starts_with("/system.slice/")
}

/// The UDP sockets kept are servers: below the ephemeral range.
pub(crate) fn is_server(listener: &Listener, ephemeral_start: u16) -> bool {
    listener.protocol == Protocol::Tcp || listener.port < ephemeral_start
}

/// Joins what was read into the report lists.
pub(crate) fn assemble(inputs: &Inputs) -> HostServicesScan {
    let programs = |unit: &str| -> BTreeSet<&str> {
        inputs
            .processes
            .get(unit)
            .into_iter()
            .flatten()
            .map(|p| p.comm.as_str())
            .collect()
    };
    let mut seen = BTreeSet::new();
    let mut listeners = Vec::new();
    for listener in inputs
        .listeners
        .iter()
        .filter(|listener| is_server(listener, inputs.ephemeral_start))
    {
        if !seen.insert((listener.protocol, listener.address, listener.port)) {
            continue;
        }
        let by_cgroup = inputs
            .socket_cgroups
            .as_ref()
            .and_then(|sockets| sockets.get(&listener.inode))
            .and_then(|id| inputs.cgroups.get(id))
            .and_then(|path| unit_path(path));
        // The exact holder (opt-in) wins: also for a socket systemd opened
        // for an activated service, whose own cgroup is init.scope.
        let exact = inputs.socket_owners.get(&listener.inode);
        let unit = exact
            .and_then(|(_, cgroup)| unit_path(cgroup.as_deref()?))
            .or(by_cgroup);
        let program = match exact {
            Some((comm, _)) => Some(comm.clone()),
            None => unit.and_then(|unit| {
                let names = programs(unit);
                (names.len() == 1).then(|| names.into_iter().next().unwrap_or_default().to_owned())
            }),
        };
        listeners.push(ServiceListener {
            protocol: match listener.protocol {
                Protocol::Tcp => ListenerProtocol::Tcp,
                Protocol::Udp => ListenerProtocol::Udp,
            },
            address: listener.address,
            port: listener.port,
            exposed: !(listener.address.is_loopback() || is_mapped_loopback(listener.address)),
            service: unit.map(|unit| unit_name(unit).to_owned()),
            program,
        });
    }
    let services = inputs
        .processes
        .iter()
        .filter(|(unit, processes)| is_system(unit) && !processes.is_empty())
        .map(|(unit, processes)| {
            let main = processes.iter().min_by_key(|p| p.pid);
            HostService {
                unit: unit_name(unit).to_owned(),
                programs: programs(unit)
                    .into_iter()
                    .take(SERVICE_MAX_PROGRAMS)
                    .map(str::to_owned)
                    .collect(),
                processes: inputs
                    .process_counts
                    .get(unit)
                    .copied()
                    .unwrap_or_else(|| u32::try_from(processes.len()).unwrap_or(u32::MAX)),
                user: main.and_then(|p| p.uid).map(|uid| {
                    inputs
                        .users
                        .get(&uid)
                        .cloned()
                        .unwrap_or_else(|| uid.to_string())
                }),
            }
        })
        .collect();
    HostServicesScan {
        owners: if inputs.owners_complete {
            Owners::Complete
        } else {
            Owners::Partial
        },
        listeners,
        services,
    }
}

/// uid → name from `/etc/passwd` text; the first entry for a uid wins.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn users(passwd: &str) -> HashMap<u32, String> {
    let mut users = HashMap::new();
    for line in passwd.lines() {
        let mut fields = line.split(':');
        if let (Some(name), Some(_), Some(uid)) = (fields.next(), fields.next(), fields.next())
            && let Ok(uid) = uid.parse()
            && !name.is_empty()
        {
            users.entry(uid).or_insert_with(|| name.to_owned());
        }
    }
    users
}

/// Reads the host's listeners and services, or one error when the socket
/// tables cannot be read. A failed owner lookup only makes `owners` partial.
pub fn collect_services(deadline: std::time::Instant) -> Result<HostServicesScan, CollectorError> {
    platform::inputs(deadline).map(|inputs| assemble(&inputs))
}

fn error(code: CollectorErrorCode, message: &str) -> CollectorError {
    CollectorError {
        collector: Identifier::new(SOURCE).expect("static collector id"),
        code,
        message: message.to_owned(),
        retryable: code != CollectorErrorCode::Unsupported,
    }
}

#[cfg(target_os = "linux")]
mod fds;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(not(target_os = "linux"))]
mod platform {
    use openvibes_core::{CollectorError, CollectorErrorCode};

    pub(super) fn inputs(_deadline: std::time::Instant) -> Result<super::Inputs, CollectorError> {
        Err(super::error(
            CollectorErrorCode::Unsupported,
            "services are not collected on this OS yet",
        ))
    }
}

#[cfg(test)]
mod tests;
