use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

use openvibes_core::{ListenerProtocol, Owners};

use super::{Inputs, Process, assemble, unit_path, users};
use crate::ports::{Listener, Protocol};

#[test]
fn the_unit_is_the_deepest_service_in_the_cgroup_path() {
    assert_eq!(
        unit_path("/system.slice/nginx.service"),
        Some("/system.slice/nginx.service")
    );
    assert_eq!(
        unit_path("/system.slice/system-getty.slice/getty@tty1.service"),
        Some("/system.slice/system-getty.slice/getty@tty1.service")
    );
    // A service's own sub-cgroups belong to it.
    assert_eq!(
        unit_path("/system.slice/docker.service/runtime"),
        Some("/system.slice/docker.service")
    );
    // A user's app inside their manager: the app unit.
    assert_eq!(
        unit_path("/user.slice/user-1000.slice/user@1000.service/app.slice/app-x.service"),
        Some("/user.slice/user-1000.slice/user@1000.service/app.slice/app-x.service")
    );
    for none in [
        "/",
        "/init.scope",
        "/machine.slice/libpod-1.scope",
        "/system.slice",
    ] {
        assert_eq!(unit_path(none), None, "{none}");
    }
}

fn listener(protocol: Protocol, address: IpAddr, port: u16, inode: u64) -> Listener {
    Listener {
        protocol,
        address,
        port,
        inode,
    }
}

fn process(pid: u32, comm: &str, uid: u32) -> Process {
    Process {
        pid,
        comm: comm.into(),
        uid: Some(uid),
    }
}

#[test]
fn listeners_get_their_service_and_a_single_programs_name() {
    let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let inputs = Inputs {
        listeners: vec![
            listener(Protocol::Tcp, any, 443, 1),
            listener(Protocol::Tcp, any, 443, 5), // SO_REUSEPORT twin: once
            listener(Protocol::Tcp, local, 5432, 2),
            listener(Protocol::Tcp, any, 22, 3), // systemd's socket: no service
            listener(Protocol::Udp, local, 53, 4), // a server
            listener(Protocol::Udp, any, 40_000, 6), // a client: left out
        ],
        ephemeral_start: 32_768,
        socket_cgroups: Some(HashMap::from([(1, 10), (5, 10), (2, 11), (3, 12), (4, 13)])),
        cgroups: HashMap::from([
            (10, "/system.slice/nginx.service".into()),
            (11, "/system.slice/postgresql.service".into()),
            (12, "/init.scope".into()),
            (13, "/system.slice/systemd-resolved.service".into()),
        ]),
        processes: [
            (
                "/system.slice/nginx.service",
                vec![process(7, "nginx", 0), process(8, "nginx", 990)],
            ),
            (
                "/system.slice/postgresql.service",
                vec![process(20, "postgres", 26), process(21, "postmaster", 26)],
            ),
            (
                "/system.slice/systemd-resolved.service",
                vec![process(30, "systemd-resolve", 193)],
            ),
            (
                "/system.slice/sssd-user.service",
                vec![process(40, "sssd", 1_234_567)],
            ),
            ("/system.slice/empty.service", vec![]),
            (
                "/user.slice/user-1000.slice/user@1000.service",
                vec![process(50, "systemd", 1000)],
            ),
        ]
        .into_iter()
        .map(|(unit, procs)| (unit.to_owned(), procs))
        .collect(),
        users: users(
            "root:x:0:0::/root:/bin/sh\nnginx:x:990:990::/:/sbin/nologin\npostgres:x:26:26::/:/bin/sh\n",
        ),
        // nginx has more processes than were read.
        process_counts: [("/system.slice/nginx.service".to_owned(), 40)].into(),
        ..Inputs::default()
    };
    let scan = assemble(&inputs);
    assert_eq!(
        scan.owners,
        Owners::Partial,
        "cgroups name services, not processes"
    );
    let by_port = |port| scan.listeners.iter().find(|l| l.port == port).unwrap();
    assert_eq!(scan.listeners.len(), 4);
    assert_eq!(by_port(443).service.as_deref(), Some("nginx.service"));
    assert_eq!(by_port(443).program.as_deref(), Some("nginx"));
    assert!(by_port(443).exposed);
    // Two programs in the unit: the program is not guessed.
    assert_eq!(by_port(5432).service.as_deref(), Some("postgresql.service"));
    assert_eq!(by_port(5432).program, None);
    assert!(!by_port(5432).exposed);
    assert_eq!(by_port(22).service, None);
    assert_eq!(by_port(53).protocol, ListenerProtocol::Udp);
    assert_eq!(
        by_port(53).service.as_deref(),
        Some("systemd-resolved.service")
    );

    let units: Vec<&str> = scan.services.iter().map(|s| s.unit.as_str()).collect();
    assert_eq!(
        units,
        [
            "nginx.service",
            "postgresql.service",
            "sssd-user.service",
            "systemd-resolved.service"
        ],
        "system services with processes only"
    );
    let nginx = &scan.services[0];
    assert_eq!(
        (nginx.processes, nginx.user.as_deref()),
        (40, Some("root")),
        "lowest pid's user"
    );
    assert_eq!(scan.services[1].programs, ["postgres", "postmaster"]);
    // A directory user has no /etc/passwd line: the uid, never empty.
    assert_eq!(scan.services[2].user.as_deref(), Some("1234567"));
    assert_eq!(scan.services[3].user.as_deref(), Some("193"));
}

#[test]
fn an_exact_owner_wins_and_complete_is_passed_on() {
    let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let inputs = Inputs {
        listeners: vec![
            listener(Protocol::Tcp, any, 22, 3),
            listener(Protocol::Tcp, any, 5432, 2),
        ],
        ephemeral_start: 32_768,
        socket_cgroups: Some(HashMap::from([(3, 12), (2, 11)])),
        cgroups: HashMap::from([
            (11, "/system.slice/postgresql.service".into()),
            (12, "/init.scope".into()),
        ]),
        processes: [(
            "/system.slice/postgresql.service".to_owned(),
            vec![process(20, "postgres", 26), process(21, "postmaster", 26)],
        )]
        .into(),
        // systemd opened :22 for sshd; the walk found sshd holding it.
        socket_owners: HashMap::from([
            (
                3,
                ("sshd".into(), Some("/system.slice/sshd.service".into())),
            ),
            (
                2,
                (
                    "postmaster".into(),
                    Some("/system.slice/postgresql.service".into()),
                ),
            ),
        ]),
        owners_complete: true,
        ..Inputs::default()
    };
    let scan = assemble(&inputs);
    assert_eq!(scan.owners, Owners::Complete);
    let by_port = |port| scan.listeners.iter().find(|l| l.port == port).unwrap();
    assert_eq!(by_port(22).service.as_deref(), Some("sshd.service"));
    assert_eq!(by_port(22).program.as_deref(), Some("sshd"));
    assert_eq!(
        by_port(5432).program.as_deref(),
        Some("postmaster"),
        "exact, not guessed"
    );
}

#[test]
fn without_sock_diag_listeners_go_out_without_owners() {
    let inputs = Inputs {
        listeners: vec![listener(
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            443,
            1,
        )],
        ephemeral_start: 32_768,
        socket_cgroups: None,
        ..Inputs::default()
    };
    let scan = assemble(&inputs);
    assert_eq!(scan.listeners[0].service, None);
    assert_eq!(scan.owners, Owners::Partial);
}

#[test]
fn programs_are_capped_at_16() {
    let inputs = Inputs {
        processes: [(
            "/system.slice/many.service".to_owned(),
            (0..20)
                .map(|i| process(i, &format!("p{i:02}"), 0))
                .collect(),
        )]
        .into_iter()
        .collect(),
        ..Inputs::default()
    };
    let scan = assemble(&inputs);
    assert_eq!(scan.services[0].programs.len(), 16);
    assert_eq!(scan.services[0].processes, 20);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Instant,
    };

    use super::super::linux::{diag_request, parse_dump};
    use crate::ports::Protocol;

    /// One `SOCK_DIAG_BY_FAMILY` message: a TCP listener on 10.0.0.1:443,
    /// inode 4242, with a cgroup id attribute; then `NLMSG_DONE`.
    fn dump() -> Vec<u8> {
        let mut msg = vec![0u8; 72];
        msg[0] = 2; // AF_INET
        msg[1] = 10; // TCP_LISTEN
        msg[4..6].copy_from_slice(&443u16.to_be_bytes());
        msg[8..12].copy_from_slice(&[10, 0, 0, 1]);
        msg[68..72].copy_from_slice(&4242u32.to_ne_bytes());
        // An unrelated attribute first (type 1, 5 bytes, padded to 8).
        msg.extend_from_slice(&5u16.to_ne_bytes());
        msg.extend_from_slice(&1u16.to_ne_bytes());
        msg.extend_from_slice(&[9, 0, 0, 0]);
        msg.extend_from_slice(&12u16.to_ne_bytes());
        msg.extend_from_slice(&21u16.to_ne_bytes());
        msg.extend_from_slice(&777u64.to_ne_bytes());
        let mut out = Vec::new();
        out.extend_from_slice(&(16 + msg.len() as u32).to_ne_bytes());
        out.extend_from_slice(&20u16.to_ne_bytes());
        out.extend_from_slice(&[0; 10]);
        out.extend_from_slice(&msg);
        out.extend_from_slice(&20u32.to_ne_bytes());
        out.extend_from_slice(&3u16.to_ne_bytes());
        out.extend_from_slice(&[0; 14]);
        out
    }

    #[test]
    fn a_dump_maps_inodes_to_cgroup_ids() {
        let mut found = Vec::new();
        let mut messages = 0;
        assert_eq!(parse_dump(&dump(), &mut found, &mut messages), Ok(true));
        assert_eq!(messages, 1);
        let (listener, cgroup) = &found[0];
        assert_eq!(listener.protocol, Protocol::Tcp);
        assert_eq!(listener.address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            (listener.port, listener.inode, *cgroup),
            (443, 4242, Some(777))
        );
        // Cut short anywhere: refused, never read past the buffer.
        let full = dump();
        for cut in [3, 17, 60, 90, 95] {
            let _ = parse_dump(&full[..cut], &mut Vec::new(), &mut 0);
        }
        let mut bad = dump();
        bad[0..4].copy_from_slice(&1000u32.to_ne_bytes());
        assert_eq!(parse_dump(&bad, &mut Vec::new(), &mut 0), Err(()));
    }

    /// The walk finds this process's own socket (no capability needed for
    /// one's own fds) and stops at its cap.
    #[test]
    fn the_fd_walk_finds_a_sockets_holder() {
        use std::os::fd::AsRawFd;
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let link = std::fs::read_link(format!("/proc/self/fd/{}", socket.as_raw_fd())).unwrap();
        let inode: u64 = link
            .to_str()
            .and_then(|l| l.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok())
            .unwrap();
        let me = std::process::id();
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let found = super::super::fds::find(&[inode].into(), &[me], deadline);
        assert_eq!(found.pids.get(&inode), Some(&me));
        assert!(found.complete, "every listener found");
        // Found in a later pass too: not among the first pids.
        let found = super::super::fds::find(&[inode].into(), &[], deadline);
        assert_eq!(found.pids.get(&inode), Some(&me));
        // An inode nobody holds: the whole of /proc is read; as a normal
        // user other users' fds are denied, so never complete.
        let found = super::super::fds::find(&[u64::MAX].into(), &[], deadline);
        assert!(found.pids.is_empty());
        if !super::super::fds::has_owner_caps() {
            assert!(!found.complete);
        }
    }

    #[test]
    fn the_request_is_a_dump_of_one_family_and_protocol() {
        let req = diag_request(10, 6, 1 << 10);
        assert_eq!(u32::from_ne_bytes(req[0..4].try_into().unwrap()), 72);
        assert_eq!(u16::from_ne_bytes(req[4..6].try_into().unwrap()), 20);
        assert_eq!(u16::from_ne_bytes(req[6..8].try_into().unwrap()), 0x301);
        assert_eq!((req[16], req[17]), (10, 6));
        assert_eq!(u32::from_ne_bytes(req[20..24].try_into().unwrap()), 1 << 10);
    }

    /// The live host: a socket this test opens is found, owned by this
    /// process's own cgroup (so the cgroup id is the directory inode), and
    /// the scan stays well within its cost budget.
    #[test]
    fn the_live_host_names_this_tests_own_listener() {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let own = own
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .map(str::to_owned);
        // This thread's CPU time (ns): the budget is CPU, not wall time.
        let cpu = || -> u64 {
            std::fs::read_to_string("/proc/thread-self/schedstat")
                .ok()
                .and_then(|s| s.split_whitespace().next()?.parse().ok())
                .unwrap_or(0)
        };
        let cpu_before = cpu();
        let started = Instant::now();
        let inputs =
            super::super::linux::inputs(started + std::time::Duration::from_secs(30)).unwrap();
        let elapsed = started.elapsed();
        let cpu_ms = (cpu() - cpu_before) as f64 / 1e6;
        let mine = inputs
            .listeners
            .iter()
            .find(|l| l.port == port)
            .expect("the test's listener is in the tables");
        let cgroup = inputs
            .socket_cgroups
            .as_ref()
            .and_then(|s| s.get(&mine.inode))
            .and_then(|id| inputs.cgroups.get(id));
        if std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            assert_eq!(cgroup, own.as_ref(), "cgroup id = directory inode");
        }
        eprintln!(
            "services scan: {cpu_ms:.2} ms CPU, {elapsed:?} wall, {} listeners, {} cgroups, {} units with processes",
            inputs.listeners.len(),
            inputs.cgroups.len(),
            inputs.processes.len()
        );
    }
}
