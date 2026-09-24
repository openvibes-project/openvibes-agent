# M6a: Linux Packaging of the Agent — Design

**Status: approved by the user on 2026-09-24.** Design discussed and
approved in conversation on 2026-09-24. Next: the implementation plan.

## 1. Goal and Exit Criteria

Milestone 6 (docs/plan/initial-implementation.md) is split into four
sub-projects, each with its own spec, plan, and build:

| # | Sub-project | Status |
|---|---|---|
| **A** | **Linux packaging (this spec)** | designing |
| B | Release pipeline: target builds (incl. aarch64), license and source policy, checksums, signatures, SBOM, provenance | later |
| C | Windows service (identity, state-dir ACLs, installer, tests) | later |
| D | macOS launchd (identity, pkg, tests) | later |

A comes first because it lets an operator install the whole system by hand
(platform RPMs plus the agent RPM) and see findings, and because B is best
designed against a real artifact.

A is done when:
1. An `openvibes-agent` RPM for Fedora 44 x86_64 installs a hardened systemd
   service that runs as the unprivileged user `openvibes_agent` with no
   capabilities.
2. Under that unit, the process, package, and port collectors still see the
   whole host (a test proves it; the sandbox must not blind them).
3. Install, upgrade, downgrade (rollback), and uninstall are tested under a
   real systemd, and state and configuration survive each step.
4. The agent, ingest, and distribution RPMs, installed together under systemd,
   enroll, fetch rules, and deliver findings (platform CI).
5. A written walkthrough takes an operator from empty Fedora hosts to
   findings in the platform.

Out of scope: aarch64 and other targets, `.deb`, signing, SBOM, provenance
(sub-project B); a setup or enrollment command (the operator edits files).

## 2. Runtime Facts That Shape the Design

- `openvibes-agent <config.toml>` runs forever; it has no signal handler and
  SQLite state is crash-safe, so systemd's default SIGTERM stop is correct.
- The state directory must be owned by the effective user with mode 0700, and
  every ancestor owned by root or that user (`openvibes-storage::paths`).
- Linux collectors read only world-readable data: `/proc` (processes),
  the RPM or dpkg database (packages), `/proc/net` (ports). No capability is
  needed.
- The agent logs one line per event to stderr (the journal under systemd).

## 3. Package Layout (agent repository)

```
packaging/rpm/openvibes-agent.spec
packaging/rpm/openvibes-agent.service
packaging/rpm/openvibes-agent.sysusers
packaging/rpm/agent.toml            template, commented
scripts/build-rpm.sh                release build + rpmbuild -bb (binary packaging, as the platform)
scripts/check-rpm.sh                static install checks (as root)
scripts/systemd-test.sh             the systemd container tests (section 7)
```

| Path | Mode, owner |
|---|---|
| `/usr/bin/openvibes-agent` | 0755 root |
| `/usr/lib/systemd/system/openvibes-agent.service` | 0644 root |
| `/usr/lib/sysusers.d/openvibes-agent.conf` | user `openvibes_agent`, no login, home `/var/lib/openvibes-agent` |
| `/etc/openvibes-agent/` | 0750 root:openvibes_agent |
| `/etc/openvibes-agent/agent.toml` | 0640 root:openvibes_agent, `%config(noreplace)` |
| `/var/lib/openvibes-agent/` | created by `StateDirectory=` (0700 openvibes_agent) |

The operator adds `/etc/openvibes-agent/platform-ca.crt` (0644) and
`/etc/openvibes-agent/token` (0600 openvibes_agent). They are not packaged.

## 4. The Unit

- `User=openvibes_agent`, `Group=openvibes_agent`, `StateDirectory=openvibes-agent`,
  `StateDirectoryMode=0700`, `ExecStart=/usr/bin/openvibes-agent /etc/openvibes-agent/agent.toml`,
  `Restart=on-failure`, `RestartSec=30s`, `UMask=0077`, `After=network-online.target`.
- Hardening, as ingest's unit: `NoNewPrivileges`, `CapabilityBoundingSet=` (empty),
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
  `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`,
  `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `RestrictNamespaces`,
  `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`,
  `MemoryDenyWriteExecute`, `SystemCallArchitectures=native`,
  `SystemCallFilter=@system-service` and `~@privileged @resources`.
- **Deliberately not set**, with a comment in the unit: `ProtectProc=invisible`
  and `ProcSubset=pid` (they hide other users' processes and `/proc/net`),
  `PrivateNetwork` (the agent talks to the platform, and ports are read from
  the host's network namespace), `PrivateUsers` (it would map other users'
  processes to nobody).
- `systemd-analyze security` exposure must be **≤ 2.5** (ingest's unit
  scores 1.4); the measured value is recorded in the packaging doc.
- The service is installed **disabled** (Fedora preset default).

## 5. First Run (operator)

1. Install the RPM.
2. Copy the platform root CA to `/etc/openvibes-agent/platform-ca.crt`.
3. Write an enrollment token to `/etc/openvibes-agent/token`, owned by
   `openvibes_agent`, mode 0600.
4. Edit `agent.toml`: `platform_url`, optionally `distribution_url`, and
   `[[rule_sets]]` with their trusted keys. The template already points
   `state_dir`, `platform_ca_file`, and `enrollment_token_file` at the paths
   above and carries commented examples.
5. `systemctl enable --now openvibes-agent`; `journalctl -u openvibes-agent`
   shows enrollment and scans.

A misconfigured agent exits with its existing message; `Restart=on-failure`
with `RestartSec=30s` retries without flooding the journal.

## 6. Upgrade, Rollback, Uninstall

- **Upgrade:** `%systemd_postun_with_restart`; state is kept and the agent
  resumes with its identity and queue.
- **Rollback** (`dnf downgrade`): works while state schemas are unchanged.
  When a future version bumps a state schema, the older binary refuses to
  start with its existing newer-schema error; this is documented, and no
  down-migrations are built.
- **Uninstall:** stops and disables the service; keeps `/var/lib/openvibes-agent`
  (identity and queue) and an edited `agent.toml` (`.rpmsave`). Purging is a
  documented `rm -r /var/lib/openvibes-agent /etc/openvibes-agent`. The
  sysusers user remains, as is Fedora practice.

## 7. Tests

CI option chosen by the user: **real systemd in a container**. podman runs
`fedora:44` with systemd as PID 1 (`--systemd=always`, `/sbin/init`); the
same script runs locally. This also resolves the platform's open decision
"systemd in CI".

**Agent repository, new CI job** (`scripts/systemd-test.sh`):
1. Build the RPM; install it; `check-rpm.sh`: user, modes, `%config(noreplace)`,
   `systemd-analyze verify`, exposure ≤ 2.5, service disabled after install.
2. **Local-only run under the unit:** configure a signed test bundle whose
   rules match `process.count`, `package.count`, and a port fact; start the
   service; within one scan, `queue.sqlite` (owned by `openvibes_agent`,
   mode 0600 inside a 0700 directory) holds findings from all three
   collectors, and `ps` shows the process as `openvibes_agent` with no
   capabilities (`/proc/PID/status` CapEff 0). Proves the sandbox does not
   blind the collectors.
3. **Upgrade** to a test build versioned 0.1.1 (same code, bumped
   `Version`): service restarted, queue and identity files unchanged,
   edited config kept.
4. **Downgrade** to 0.1.0: service runs, state intact.
5. **Uninstall:** service gone, state directory and edited config kept.

**Platform repository, CI end to end** (with the agent pin bumped to a
revision that has the packaging): build the agent RPM from the pinned
revision with the agent's `build-rpm.sh`; in the same systemd container,
install PostgreSQL, the platform RPMs, and the agent RPM; follow the
walkthrough (section 5 and the platform's first-install steps) scripted;
the agent enrolls, fetches its bundle from distribution, and its findings
appear in PostgreSQL. This is the manual install, automated.

## 8. Documentation

- Agent: `docs/components/packaging.md` (layout, unit, first run, upgrade,
  rollback, uninstall, exposure score, how to test); `workflow.md` gains the
  packaging job; the component index lists it.
- Platform: `docs/components/packaging.md` gains "Trying the whole system":
  one walkthrough from empty Fedora hosts to findings, platform and agent.
- Workspace `decisions.md`: systemd in CI (option 1).

## 9. Milestones

| # | Milestone | Exit |
|---|---|---|
| MA0 | Spec files: spec, unit, sysusers, template, build and check scripts | RPM builds; `check-rpm.sh` green in a container; exposure ≤ 2.5 |
| MA1 | systemd container harness and the local-only run under the unit | section 7 steps 1–2 green locally |
| MA2 | Upgrade, downgrade, uninstall tests; agent CI job | section 7 steps 3–5 green in agent CI |
| MA3 | Platform end to end under systemd; agent pin bump; walkthrough | platform CI green with the new job; exit criterion 5 |
