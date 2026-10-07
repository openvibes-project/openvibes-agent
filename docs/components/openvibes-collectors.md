# openvibes-collectors

## Purpose

Read-only host collectors. They observe host state and never modify it or
start an external process. Each collector returns all of its facts, or
none of them and one structured `CollectorError`, so a rule never sees a
partial list.

## Interfaces

- **`collect_processes`:** `process.names` (sorted, unique) and
  `process.count`. Linux reads `/proc`, which is world-readable. Windows and
  macOS have their own implementations; other systems report `unsupported`.
- **`collect_packages`:** `package.names` and `package.count`, from the RPM
  or dpkg database, parsed with bounds checks. Linux only. `package_facts`
  builds the facts from a package list. Packages carry their source
  package when it differs from the binary's name (protocol P10): dpkg's
  `Source` (and, for a binNMU, the source's own version), or the name in
  RPM's `SOURCERPM` (an odd value is ignored). Debian, Ubuntu and Rocky
  Linux publish vulnerabilities per source package. The RPM database is
  opened so that SQLite never creates or writes a file beside it, even as
  root: an active WAL's shared memory is read with `readonly_shm`, an idle
  database as `immutable`, with `trusted_schema` off.
- **`collect_ports`:** listening sockets per protocol (`tcp`, `udp`):
  - `port.<proto>.exposed` and `port.<proto>.exposed.count`: ports bound to
    a non-loopback address;
  - `port.<proto>.local`: ports bound only to loopback;
  - `port.<proto>.listeners`: every bound `address:port`.

  Linux reads `/proc/net`. "Exposed" describes the bind address, not
  reachability.
- **`collect_services` (P15, Linux):** the host's listening sockets and
  running systemd services for the platform (`HostServicesScan`; no facts).
  - Listeners: TCP in `LISTEN` and unconnected UDP below the ephemeral
    range (`ip_local_port_range`), so client sockets are left out, read
    from the kernel's `sock_diag` netlink dump (filtered by state in the
    kernel); `/proc/net` is the fallback.
  - Owner without privilege: `sock_diag` gives any user each socket's
    cgroup id, the inode of its `/sys/fs/cgroup` directory; the deepest
    `*.service` in that path is the `service`. `program` only when that
    unit runs a single program. Sockets systemd holds for socket
    activation sit in `init.scope`: no service. `owners` is `partial`.
  - Exact owner with the opt-in drop-in (`CAP_DAC_READ_SEARCH` and
    `CAP_SYS_PTRACE`, see the packaging page): the fd links of the
    listeners' own cgroups first, then of every system service (a socket
    systemd opened for socket activation is also held by the daemon it
    started), then of other processes while a socket has no holder at
    all, at most 1,000 links (about 4.5 µs each). A socket only systemd
    holds after that (no daemon started yet) shows program `systemd`
    and no service (the `.socket` unit's name is only in systemd's
    D-Bus API). `owners` is `complete` when every holder that exists was
    found. Without both capabilities the walk is not tried.
  - Services: the `*.service` cgroups under `/system.slice` with
    processes; their `comm`s (the lowest 64 pids read per unit, at most 16
    names), the process count from `cgroup.procs`, and the real uid of the
    lowest pid as a name from `/etc/passwd`, or the decimal uid when it has
    none there (directory users).
  - Cost (release, a busy desktop with 240 cgroups and 400 service
    processes): about 10 ms CPU, mostly the cgroup walk and `comm`
    reads; about 1 ms in a small fedora:44 system (`services-e2e.sh`).
    Only `/system.slice` is walked unless a listener's cgroup is
    elsewhere.
- **`os_release`:** the host's `ID` and `VERSION_ID` from `/etc/os-release`
  (falling back to `/usr/lib/os-release`, at most 64 KiB read), for the
  inventory report. `None` when neither file exists, a key is missing (a
  rolling distribution has no `VERSION_ID`), or a value is not an identifier.
- **`running_kernel`:** the running kernel's release as `uname -r` prints
  it (the `uname` system call, no file read), for the inventory report
  (protocol P9). `None` if it has characters the schema does not allow.
- **`hostname`:** the OS-reported host name, or `None` if it is empty. It
  is an operator label and never identity.
- **`process_events` (P14, Linux):** process starts from the kernel audit
  system, for alarms.
  - `open_audit_socket` binds a `NETLINK_AUDIT` socket to the read-only
    multicast group. That needs `CAP_AUDIT_READ` and nothing else. The
    agent never changes audit rules and never reads `/var/log/audit`.
    Records arrive only while the packaged rule
    (`-S execve,execveat -k openvibes-exec`) is loaded. Only messages from
    the kernel (netlink port 0) are read.
  - `Joiner` joins each event's `SYSCALL`, `EXECVE` and `CWD` records
    (joined on the serial, up to `EOE`) into a `ProcessStart`. It takes
    successful execs carrying the key and ignores everything else. It
    decodes quoted and hex values and reassembles `aN_len`/`aN[i]`
    pieces, even across records. Values stay raw bytes; decoding them is
    the agent's job. Hex past the 64 KiB argument budget is checked but
    not decoded, so a padded argument costs little more than one that
    fits (a crafted 64 KiB start: 229 µs before, 54 µs after, board
    #106).
  - `spawn_reader` runs the reader thread: `spawn_forwarder` (parent lookup, recent-exec set, `try_send`, drop counts) fed by `AuditStarts`, the audit half behind the `StartSource` trait that an eBPF source will also implement. It reads each start's parent
    from `/proc` as soon as the event is joined, because a short-lived
    parent may be gone by the time the engine gets to it. It skips parents
    it saw exec among the last 4,096 execs (the engine's table has them).
    Limits: a parent that has already exited when its child's exec
    record is joined (a quick loop of children, read while the reader is
    behind on a busy host) is gone, and that start has no parent; only
    the direct parent is snapshotted, so a fast-exiting
    wrapper chain (`sudo` → `sh`) can still lose grandparents; and a
    parent whose pid was reused before the snapshot is a stranger (a
    starttime check would catch it; not done yet). The agent's process
    table keeps an exited process for 60 s, so a descendant that execs
    later than that after an ancestor exited (a forked worker of a
    crashed master) has its lineage end there. It hands the
    start on with `try_send` and never waits on the engine.
  - `read_process` reads one pid from `/proc`: `comm`, ppid, real and
    effective uid, the command line (cut at 4 KiB), and `exe`/`cwd` when
    this identity may read them. The agent calls it for a parent it never
    saw exec: one started before the agent, or a worker forked without
    exec, like nginx or php-fpm workers.
  - `ebpf::OBJECT` (feature `ebpf`, Linux only): the compiled
    `openvibes-agent-ebpf` program, built by `build.rs` with `aya-build`
    (needs the eBPF crate's pinned nightly and `bpf-linker`; see
    [openvibes-agent-ebpf.md](openvibes-agent-ebpf.md)).

## Configuration

None. Callers pass a deadline and `ResourceLimits`.

## Failure behaviour

Any of these yields no facts and one `CollectorError` with a fixed code
(`PermissionDenied`, `NotFound`, `TimedOut`, `InvalidData`, `Unsupported`,
`Internal`) and a bounded message:
- an unreadable or malformed source;
- a passed deadline;
- more values than the 10,000-item fact list limit (packages: more than
  50,000, the inventory limit; `package.names` may hold that many).

The rules engine treats facts from a failed collector as unavailable, never
as compliant.

`process_events` loses events rather than block the kernel or grow
without bound. Every loss is counted in `health.alarms.events_dropped_total`:
- a full channel to the engine (4,096 starts);
- a kernel `ENOBUFS`, when the socket buffer overflowed (counted once;
  reading goes on);
- an event with no `EOE` after 1 s;
- the oldest of more than 64 unfinished events.

Arguments past 64 KiB are cut and the start is marked truncated, but it
is still evaluated, so padding a command line does not hide it. Opening
the socket without the capability is `permission_denied`. Without kernel
audit it is `unsupported`; the agent then runs without alarms.

Noisy programs: exclude them in the kernel, before the agent sees them.
Put `-a never,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/prog`
in a rules file that sorts before `openvibes-agent.rules` in
`/etc/audit/rules.d`, then run `augenrules --load`.

`collect_services` fails only when the socket tables cannot be read at
all; a failed `sock_diag` dump (owners left out), a cgroup v1 host (no
owners, no services), a process that exits during the read, or the fd walk
cap only make the report less complete, never absent.

## Test

```sh
cargo test --locked -p openvibes-collectors
```

The audit records in the unit tests are synthetic, written in the kernel's
format (quoting, hex, split arguments). A mutation loop feeds 100,000
corrupted messages through the parser and checks it never panics. The CI
job `alarms-kernel` (`scripts/alarms-kernel-e2e.sh`) checks the format on
a real kernel. The `services` tests parse a synthetic `sock_diag` dump
(cut short anywhere, never read past the buffer), join synthetic inputs,
and on the live host find the test's own listener in its own cgroup, which
checks that a cgroup id is its directory's inode; the fd walk finds the
test's own socket and stops at its cap. `scripts/services-e2e.sh` runs the
probe under the packaged unit with and without the drop-in.
