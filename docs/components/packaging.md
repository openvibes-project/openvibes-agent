# packaging (Fedora RPM)

## Purpose

Installs `openvibes-agent` as a hardened systemd service on Fedora 44 x86_64,
running as the unprivileged user `openvibes_agent` with no capabilities
(M6 sub-project A; spec `docs/specs/2026-09-24-m6a-linux-packaging-design.md`).
Other platforms and signed release artifacts are later M6 sub-projects.

```sh
scripts/build-rpm.sh     # → target/rpm/RPMS/x86_64/openvibes-agent-*.rpm
```

`build-rpm.sh` builds the release binary (default features, so with the
eBPF program: run `scripts/ebpf-tools.sh` first for its nightly and
`bpf-linker`) and wraps it with `rpmbuild -bb`;
the spec only installs files. `OV_VERSION=x.y.z` overrides the package
version (the upgrade tests build a newer package from the same code).

## Contents

| Path | Mode, owner |
|---|---|
| `/usr/bin/openvibes-agent` | 0755 root |
| `/usr/lib/systemd/system/openvibes-agent.service` | 0644 root |
| `/usr/lib/sysusers.d/openvibes-agent.conf` | user `openvibes_agent` |
| `/etc/openvibes-agent/` | 0750 root:openvibes_agent |
| `/etc/openvibes-agent/agent.toml` | 0640 root:openvibes_agent, `%config(noreplace)` |
| `/usr/share/openvibes-agent/openvibes-agent.rules` | 0644 root, the exec audit rule template; copied to `/etc/audit/rules.d` (0640) on fallback hosts only |
| `/usr/libexec/openvibes-agent/audit-setup`, `audit-fallback` | 0755 root, the audit-rule logic (below) |
| `/var/lib/openvibes-agent/` | 0700 openvibes_agent, created by `StateDirectory=` |
| `/usr/share/doc/openvibes-agent/owners.conf` | 0644 root, the opt-in drop-in below; not enabled (P15) |

The operator adds `platform-ca.crt` and `token` (0600, owner
`openvibes_agent`) to `/etc/openvibes-agent/`. The shipped `agent.toml`
names them and a placeholder `platform_url`; the agent refuses to start
until the CA file exists and the values are edited.

## The unit

`openvibes-agent.service` runs `/usr/bin/openvibes-agent
/etc/openvibes-agent/agent.toml` as `openvibes_agent`, `Restart=on-failure`
every 30 s, with `NoNewPrivileges`, three capabilities (ambient and
bounding; see below),
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
kernel, cgroup, and clock protection, `RestrictAddressFamilies=AF_INET
AF_INET6 AF_UNIX AF_NETLINK`, `RestrictNamespaces`, `MemoryDenyWriteExecute`, and the
`@system-service` syscall filter without `@privileged @resources`, except
`bpf` and `capset`, with `SystemCallErrorNumber=EPERM`.
`systemd-analyze security` exposure: **1.8** (limit 2.5; 1.4 before the
audit capability, 1.7 before the eBPF capabilities). `scripts/check-unit.sh` checks the capability lines,
`AF_NETLINK`, `NoNewPrivileges`, a non-root `User=`, the `bpf capset` and
`perf_event_open` filter lines, `SystemCallErrorNumber` and the rule file
statically in the RPM job.

**Capabilities (process starts, P14).** The agent reads process starts
with its eBPF program, and from kernel audit when that cannot load
(design: `docs/specs/2026-10-08-ebpf-process-watcher-design.md`):
- `CAP_BPF` and `CAP_PERFMON` load and attach the eBPF exec program. They
  allow loading tracing programs, that is reading kernel memory, so the
  agent drops both from every set on its main thread right after attach,
  before it starts any other thread, then checks every thread in
  `/proc/self/task`. It drops them the same way when eBPF is not used (the
  audit fallback, `process_events` off, no platform). If the drop fails,
  on any path, the agent does not start (`cannot start: cannot drop
  CAP_BPF and CAP_PERFMON: …`; fail closed). They stay only in
  the bounding set (clearing it needs `CAP_SETPCAP`, not granted); with
  the other sets empty, a non-root user and `NoNewPrivileges`, nothing can
  raise them again. Running, the agent holds `CAP_AUDIT_READ` only.
- `CAP_AUDIT_READ` reads process starts from the audit multicast group,
  the fallback; it cannot change audit rules or read `/var/log/audit`.

**Memory after the eBPF load.** Loading needs tens of MB of heap for a
moment (the kernel's BTF, read once). With glibc's dynamic malloc
thresholds, which freeing a large buffer raises, much of it stays resident:
a 6 MB heap with aya parsing the whole kernel BTF, 17 MB with the
attach-only BTF the loader now hands it (its stub table grows by
doubling), against 5 MB with the thresholds pinned (measured on Fedora
6.19, 2026-10-08). `Environment=GLIBC_TUNABLES=glibc.malloc.mmap_threshold=131072:glibc.malloc.trim_threshold=131072`
pins both at 128 KiB, so it goes back to the system (the eBPF agent's heap
then matches the audit agent's). Other C libraries ignore it.
`check-unit.sh` checks the line.

**Why `bpf` and `capset` are allowed.** Both are in `@privileged`, which
the filter denies; a later `SystemCallFilter=bpf capset` line re-allows
those two calls (systemd applies the lines in order). `bpf()` loads and
attaches the program; `capset()` drops `CAP_BPF` and `CAP_PERFMON` after
(without `CAP_SETPCAP` it can only lower capabilities, never raise them).
Without `capset` the drop fails with `EPERM` and the agent refuses to
start (seen in the lab before it was allowed). The program attaches as a BTF
tracepoint through `bpf()` alone, so `perf_event_open` stays denied.
`SystemCallErrorNumber=EPERM` makes any call the filter blocks fail with
`EPERM` instead of killing the agent with `SIGSYS`: a filter that blocked
`bpf` would otherwise kill the eBPF attempt and the agent with it, into a
restart loop, where now the agent falls back to audit. CI job
`alarms-cost` fails unless the packaged agent under this unit reads
process starts with eBPF.

Deliberately not set, because the agent inspects the host:
`ProtectProc=invisible` and `ProcSubset=pid` (they hide other users'
processes and `/proc/net`), `PrivateNetwork`, `PrivateUsers`, and
`ProtectHostname` (it would freeze the reported hostname at its value when
the service started; the capability set, which holds only
`CAP_AUDIT_READ` once the eBPF capabilities are dropped, already prevents
setting it).
`check-rpm.sh` refuses a unit that sets them.

The service is installed disabled. It stops with SIGTERM (state is
crash-safe SQLite).

## The exec audit rule: fallback hosts only

Process starts come from the agent's own eBPF program when the kernel
allows it: `/sys/kernel/btf/vmlinux` exists and the kernel is 5.8 or later
(an *eBPF host*). There the package loads no audit rule and touches no
audit setting. Other hosts use kernel audit as the fallback, and only there
does the package set audit up.

All of this lives in one script,
`/usr/libexec/openvibes-agent/audit-setup decide|apply|fallback|remove`;
the scriptlets only call it:

- `%posttrans` runs `audit-setup apply` after the whole transaction. On a
  fallback host it copies the template
  `/usr/share/openvibes-agent/openvibes-agent.rules` to
  `/etc/audit/rules.d/openvibes-agent.rules` (0640; logs every successful
  `execve`/`execveat`, 64- and 32-bit, key `openvibes-exec`) and comments
  out `-a task,never` / `-a never,task` in every
  `/etc/audit/rules.d/*.rules`, prefixing it
  `# disabled by openvibes-agent (exec alarms need it off): `. Fedora's
  default rules contain `-a task,never`, which stops the kernel auditing
  any program start. On an eBPF host it undoes both: every line carrying
  that prefix is restored, and the copied rule is deleted when unchanged
  from the template (an edited copy is kept and reported).
- Then it runs `augenrules --load` if auditd is running, and otherwise
  prints `load them with: augenrules --load`. `augenrules --load` rebuilds
  the kernel's rules from `/etc/audit/rules.d`, so rules added by hand
  with `auditctl` and never saved there are replaced.
- `%preun` on erase runs `audit-setup remove`: the same undo.
- `manage_audit_rules = false` in `agent.toml` (read by the script only,
  not the agent) leaves audit rules as they are on every host, in both
  directions. The agent itself never changes audit rules.
- In a chroot (an image built with `dnf --installroot` or mock) the script
  decides nothing, since it would see the build host's kernel: run
  `audit-setup apply` once on the booted host.
- `audit-setup` rewrites a rules file through a temporary copy beside it,
  renamed over it, so a full disk never leaves it truncated.
- `/usr/libexec/openvibes-agent/audit-fallback` (root) sets the fallback up
  on any host, for an admin who wants audit as the source.

**Upgrading from 0.2.5.** 0.2.5 owned `/etc/audit/rules.d/openvibes-agent.rules`
as `%config(noreplace)` and commented out `task,never` on every host. The
new package no longer owns the file, so rpm erases it when unchanged and
renames an edited copy to `openvibes-agent.rules.rpmsave`, which `augenrules`
does not read; `%posttrans` says so. On an eBPF host that is wanted: the
exec rule only cost an auditd disk write per program start. `audit-setup
apply` then restores the lines 0.2.5 commented out. On a fallback host it
installs the template again (copy your edit back from `.rpmsave` if you
want it).

**A kernel that gains BTF** turns a fallback host into an eBPF host. The
agent switches to eBPF at its next start, while the exec rule keeps
loading (cost only) until the next package update or `audit-setup apply`
undoes it.

Notes for fallback hosts:

- The agent's log line "process starts lost before evaluation" names the
  cause: audit socket overflows (the kernel's buffer filled), events
  without an end record within a second, or a full engine queue.
- With the rule loaded and auditd stopped, the kernel sends every exec
  record to the kernel log instead, which floods the journal on a busy
  host. Keep auditd running, or, if you turn process events off, run
  `audit-setup remove` (or set `manage_audit_rules = false` and delete the
  rule yourself) and `augenrules --load`.
- To quiet a noisy program, see the collectors page (`-a never,exit`).

## Exact port owners: the opt-in drop-in (P15)

By default the agent already shows, for every listening port, the systemd
**service** that owns it, with no extra privilege: the kernel tells any
user which cgroup a socket belongs to (`sock_diag`). It names the program
too when that service runs a single program.

To name the exact **program** behind every port, the agent has to read
other users' `/proc/PID/fd`. That needs two capabilities together; either
one alone is not enough (tested 2026-10-01). On a host installed without
documentation (`tsflags=nodocs`, as in container images) the file is not
on disk; take `packaging/rpm/owners.conf` from the agent repository.

```sh
install -D -m 0644 /usr/share/doc/openvibes-agent/owners.conf \
    /etc/systemd/system/openvibes-agent.service.d/owners.conf
systemctl daemon-reload && systemctl restart openvibes-agent
```

**The risk, plainly:** `CAP_DAC_READ_SEARCH` lets the agent read **every
file on the host** (password hashes, private keys, other users' files),
and `CAP_SYS_PTRACE` lets it **attach to any process, root's included**,
and so run code as that process. If the agent were ever compromised, with
this drop-in an attacker would be close to root on the host. Without it,
a compromised agent can read only what the `openvibes_agent` user can, and
listen to process starts. Enable it only where exact program names are
worth that, and remove the file to go back:

```sh
rm /etc/systemd/system/openvibes-agent.service.d/owners.conf
systemctl daemon-reload && systemctl restart openvibes-agent
```

**The cost:** with the drop-in each hourly scan also reads the open
files of the listeners' services and every other system service to name
the exact holders: about 10 ms of CPU on the CI VM (2.7–3.4 ms without
it), at most 1,000 fd links per scan. `owners` in the agent's report is
`complete` when every holder was found, and stays `partial` past the cap. `NoNewPrivileges` and the
rest of the sandbox stay as they are; the drop-in only adds the two
capabilities to the ambient and bounding sets.

## First run

1. `dnf install openvibes-agent-*.rpm`
2. Copy the platform root CA to `/etc/openvibes-agent/platform-ca.crt`.
3. Write the enrollment token:
   `install -o openvibes_agent -g openvibes_agent -m 0600 token /etc/openvibes-agent/token`
4. Edit `/etc/openvibes-agent/agent.toml`: `platform_url`, optionally
   `distribution_url`, and `[[rule_sets]]` with their trusted keys.
5. `systemctl enable --now openvibes-agent`; `journalctl -u openvibes-agent`
   shows enrollment and scans.

## Releases

A tag `vX.Y.Z` equal to the workspace version runs
`.github/workflows/release.yml`: the RPM is built in `fedora:44`, signed with
the OpenVIBES package key (organisation secrets `RPM_SIGNING_KEY`,
`RPM_SIGNING_PASSPHRASE`) and checked against the committed public key
`packaging/rpm/openvibes-packages.gpg` by `scripts/sign-rpms.sh` (the same
script as the platform's; `scripts/test-sign-rpms.sh` tests it in CI). The
GitHub Release is a draft until that check passes; the package
repository `openvibes-project.github.io` picks the release up on its
30-minute schedule (no token). If a release for the tag already exists (made by
hand in the GitHub UI), the packages are uploaded to it instead. The installer there (`install.sh --agent`) sets up
and enrolls an agent in one command. Spec: openvibes-platform
`docs/specs/2026-09-27-releases-design.md`.

## Failure behaviour

- A missing CA file or invalid configuration: the agent exits with its
  message; systemd retries every 30 s.
- Upgrade restarts the service; identity and queue are kept.
- Downgrade works while state schemas are unchanged; after a future schema
  bump the older binary refuses the newer state with its newer-schema error.
- Uninstall stops the service and keeps `/var/lib/openvibes-agent` and an
  edited configuration. Purge: `rm -r /var/lib/openvibes-agent /etc/openvibes-agent`.

## How to test

`scripts/check-rpm.sh` (as root, after install) checks the user, modes and
owners, `%config(noreplace)` (configuration), the audit-rule template
and scripts (and that the package owns no `/etc/audit/rules.d` file),
`systemd-analyze verify`, the forbidden
directives, the exposure limit, that the service is installed disabled, and
that the binary runs:

```sh
scripts/build-rpm.sh
podman run --rm -v "$PWD:/src:Z" -w /src registry.fedoraproject.org/fedora:44 bash -c \
  'dnf -q -y install systemd && dnf -q -y install target/rpm/RPMS/x86_64/openvibes-agent-*.rpm && bash scripts/check-rpm.sh'
```

`scripts/check-unit.sh` also checks that `owners.conf` adds exactly the
two capabilities and nothing else, and `check-rpm.sh` that it is shipped
as documentation and not enabled.

### Port owners on a real kernel (P15)

`scripts/services-e2e.sh` (CI job `services-kernel`, a VM runner with sudo)
runs a web server as `nobody` in a unit with two programs, then a probe
(the `services_probe` example) as `openvibes_agent` inside the packaged
unit's sandbox: without the drop-in the port shows its service and no
program, `owners` partial; with `owners.conf` it shows `python3`. Each run
prints its CPU time (about 1 ms and 2 ms in a fedora:44 container).

### Audit rules

`tests/packaging/audit-setup.sh` unit-tests `audit-setup` on temporary
trees (no root): the eBPF/fallback decision, set up and undo, only marked
lines restored in every file, an edited rule kept, the opt-out, and
idempotence. `scripts/audit-rules-e2e.sh RPM_DIR OLD_RPM` (CI job
`systemd`, on a host with BTF) installs the package in fresh `fedora:44`
containers: an eBPF host is left alone; an upgrade from the released 0.2.5
RPM removes its rule and restores `-a task,never`; an edited 0.2.5 rule is
saved as `.rpmsave` and reported; `audit-fallback` sets the fallback up
idempotently; erase undoes it.

### Under systemd

`scripts/systemd-test.sh [RPM_DIR]` builds the RPM (unless given a
directory) and the `sign_bundle` example, then runs podman `fedora:44`
with systemd as PID 1:

1. A probe asserts that systemd enforces the unit sandbox in this container
   (`ProtectSystem=strict` blocks a write to `/usr`); otherwise the test
   fails rather than passing on an unsandboxed service.
2. Install and `check-rpm.sh`.
3. With the shipped configuration the service fails and retries every 30 s
   (at most 3 restarts in 65 s).
4. A local-only configuration with a signed three-rule bundle: findings
   from `'systemd' in facts['process.names']` (PID 1 is root's, so other
   users' processes must be visible), `package.count >= 50` (the RPM
   database is readable), and `port.tcp.exposed.count >= 0` (the fact exists
   only if `/proc/net` was read) reach the queue; the process runs as
   `openvibes_agent` with only `CAP_AUDIT_READ` effective (the eBPF
   capabilities dropped), a seccomp filter, and `no_new_privs`,
   in the host's hostname namespace; the state directory is 0700 and the
   queue 0600.

The container runs rootless but `--privileged`: that is privilege inside
its own user namespace only, and it is what lets systemd build the unit's
mount namespaces and re-mount `/proc` paths as a real host would. Without
it systemd logs "namespace setup is prohibited" and silently runs the
service unsandboxed.

After the scan, the same container upgrades to the 0.1.1 test build,
downgrades back to 0.1.0, and removes the package. Each step must restart
the service (except removal), keep `agent.toml` byte for byte, and keep the
queued findings; removal must keep the state directory and the edited
configuration.

CI runs this as the `systemd` job on the RPMs from the `rpm` job
(`SIGN_BIN` names the prebuilt `sign_bundle`).

Each check was seen failing: `ProtectProc=invisible` in a drop-in fails
the `systemd` rule, `ProtectHostname=yes` fails the hostname check, and
`InaccessiblePaths=` on the RPM database fails the
packages rule.
