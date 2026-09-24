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
| `/var/lib/openvibes-agent/` | 0700 openvibes_agent, created by `StateDirectory=` |

The operator adds `platform-ca.crt` and `token` (0600, owner
`openvibes_agent`) to `/etc/openvibes-agent/`. The shipped `agent.toml`
names them and a placeholder `platform_url`; the agent refuses to start
until the CA file exists and the values are edited.

## The unit

`openvibes-agent.service` runs `/usr/bin/openvibes-agent
/etc/openvibes-agent/agent.toml` as `openvibes_agent`, `Restart=on-failure`
every 30 s, with `NoNewPrivileges`, an empty capability set,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
kernel, cgroup, clock, and hostname protection, `RestrictAddressFamilies=AF_INET
AF_INET6 AF_UNIX`, `RestrictNamespaces`, `MemoryDenyWriteExecute`, and the
`@system-service` syscall filter without `@privileged @resources`.
`systemd-analyze security` exposure: **1.4** (limit 2.5).

Deliberately not set, because the agent inspects the host:
`ProtectProc=invisible` and `ProcSubset=pid` (they hide other users'
processes and `/proc/net`), `PrivateNetwork`, and `PrivateUsers`.
`check-rpm.sh` refuses a unit that sets them.

The service is installed disabled. It stops with SIGTERM (state is
crash-safe SQLite).

## First run

1. `dnf install openvibes-agent-*.rpm`
2. Copy the platform root CA to `/etc/openvibes-agent/platform-ca.crt`.
3. Write the enrollment token:
   `install -o openvibes_agent -g openvibes_agent -m 0600 token /etc/openvibes-agent/token`
4. Edit `/etc/openvibes-agent/agent.toml`: `platform_url`, optionally
   `distribution_url`, and `[[rule_sets]]` with their trusted keys.
5. `systemctl enable --now openvibes-agent`; `journalctl -u openvibes-agent`
   shows enrollment and scans.

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
owners, `%config(noreplace)`, `systemd-analyze verify`, the forbidden
directives, the exposure limit, that the service is installed disabled, and
that the binary runs:

```sh
scripts/build-rpm.sh
podman run --rm -v "$PWD:/src:Z" -w /src registry.fedoraproject.org/fedora:44 bash -c \
  'dnf -q -y install systemd && dnf -q -y install target/rpm/RPMS/x86_64/openvibes-agent-*.rpm && bash scripts/check-rpm.sh'
```
