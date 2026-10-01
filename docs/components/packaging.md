# packaging (Fedora RPM)

## Purpose

Installs `openvibes-agent` as a hardened systemd service on Fedora 44 x86_64,
running as the unprivileged user `openvibes_agent` with no capabilities
(M6 sub-project A; spec `docs/specs/2026-09-24-m6a-linux-packaging-design.md`).
Other platforms and signed release artifacts are later M6 sub-projects.

```sh
scripts/build-rpm.sh     # → target/rpm/RPMS/x86_64/openvibes-agent-*.rpm
```

`build-rpm.sh` builds the release binary and wraps it with `rpmbuild -bb`;
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
| `/etc/audit/rules.d/openvibes-agent.rules` | 0640 root:root, `%config(noreplace)` (P14) |
| `/var/lib/openvibes-agent/` | 0700 openvibes_agent, created by `StateDirectory=` |
| `/usr/share/doc/openvibes-agent/owners.conf` | 0644 root, the opt-in drop-in below; not enabled (P15) |

The operator adds `platform-ca.crt` and `token` (0600, owner
`openvibes_agent`) to `/etc/openvibes-agent/`. The shipped `agent.toml`
names them and a placeholder `platform_url`; the agent refuses to start
until the CA file exists and the values are edited.

## The unit

`openvibes-agent.service` runs `/usr/bin/openvibes-agent
/etc/openvibes-agent/agent.toml` as `openvibes_agent`, `Restart=on-failure`
every 30 s, with `NoNewPrivileges`, exactly one capability
(`CAP_AUDIT_READ`, ambient and bounding, to read process starts from the
audit multicast group; P14),
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
kernel, cgroup, and clock protection, `RestrictAddressFamilies=AF_INET
AF_INET6 AF_UNIX AF_NETLINK`, `RestrictNamespaces`, `MemoryDenyWriteExecute`, and the
`@system-service` syscall filter without `@privileged @resources`.
`systemd-analyze security` exposure: **1.7** (limit 2.5; 1.4 before the
audit capability). `scripts/check-unit.sh` checks the capability lines,
`AF_NETLINK`, `NoNewPrivileges` and the rule file statically in the RPM
job.

Deliberately not set, because the agent inspects the host:
`ProtectProc=invisible` and `ProcSubset=pid` (they hide other users'
processes and `/proc/net`), `PrivateNetwork`, `PrivateUsers`, and
`ProtectHostname` (it would freeze the reported hostname at its value when
the service started; the capability set, which holds only
`CAP_AUDIT_READ`, already prevents setting it).
`check-rpm.sh` refuses a unit that sets them.

The service is installed disabled. It stops with SIGTERM (state is
crash-safe SQLite).

## The exec audit rule (P14)

`/etc/audit/rules.d/openvibes-agent.rules` asks the kernel to log every
successful `execve`/`execveat` (64- and 32-bit) with the key
`openvibes-exec`. Those records are what the agent's `process_events`
collector reads. `%post` loads it with `augenrules --load` when auditd is
running; erasing the package loads the rules again without it.

- `augenrules --load` rebuilds the kernel's rules from
  `/etc/audit/rules.d`. Rules an admin added by hand with `auditctl` and
  never saved there are replaced.
- With the rule loaded and auditd stopped, the kernel sends every exec
  record to the kernel log instead, which floods the journal on a busy
  host. Keep auditd running, or turn the rule off if you turn process
  events off: comment out the two `-a` lines in
  `/etc/audit/rules.d/openvibes-agent.rules` and run `augenrules --load`.
  Do not delete the file: rpm recreates a missing `%config(noreplace)`
  file on the next upgrade, but keeps an edited one (the new one lands
  beside it as `.rpmnew`).
- A new install lists `"process_events"` in `agent.toml`. An upgrade keeps
  the host's own `agent.toml` (`noreplace`), so alarms stay off there
  until it is added to `collectors`, while the audit rule is already
  active: auditd logs every exec to `/var/log/audit` in the meantime.
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

With the drop-in, `owners` in the agent's report is `complete` when every
listener's process was found; the walk reads at most 1,000 fd links per
scan (about 5 ms) and stays `partial` past that. `NoNewPrivileges` and the
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
owners, `%config(noreplace)` (configuration and audit rule),
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

`scripts/services-e2e.sh` (CI job `alarms-kernel`, a VM runner with sudo)
runs a web server as `nobody` in a unit with two programs, then a probe
(the `services_probe` example) as `openvibes_agent` inside the packaged
unit's sandbox: without the drop-in the port shows its service and no
program, `owners` partial; with `owners.conf` it shows `python3`. Each run
prints its CPU time (about 1 ms and 2 ms in a fedora:44 container).

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
   `openvibes_agent` with `CapEff` 0, a seccomp filter, and `no_new_privs`,
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
