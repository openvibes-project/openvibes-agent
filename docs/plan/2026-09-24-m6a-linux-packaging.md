# M6a: Linux Packaging — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A hardened `openvibes-agent` RPM for Fedora 44 x86_64, tested under a real systemd for install, sandboxed collection, upgrade, downgrade, and uninstall, and end to end with the platform RPMs.

**Architecture:**
- **Packaging:** binary packaging exactly like the platform's (`scripts/build-rpm.sh` builds a release binary, the spec only installs files).
- **Test harness:** one bash script drives a podman `fedora:44` container with systemd as PID 1 through every lifecycle step. Checks read real state: `systemctl`, `/proc/PID/status`, and the agent's `queue.sqlite`.
- **End to end:** the platform repository builds the agent RPM from its pinned revision and runs the same kind of container with PostgreSQL, ingest, distribution, and the agent.

**Tech Stack:** Rust 1.95 (release build), rpmbuild, systemd (sysusers, unit hardening), podman, bash, sqlite3, the existing `openvibes-rules` `sign_bundle` example.

**Spec:** `docs/specs/2026-09-24-m6a-linux-packaging-design.md` (approved 2026-09-24).

## Global Constraints

- **Target:** Fedora 44, x86_64 only. Package `openvibes-agent`; service user `openvibes_agent`.
- **Paths:**
  - config: `/etc/openvibes-agent/agent.toml`, 0640 `root:openvibes_agent`, `%config(noreplace)`;
  - config directory: `/etc/openvibes-agent/`, 0750 `root:openvibes_agent`;
  - state: `/var/lib/openvibes-agent`, created by `StateDirectory=` with mode 0700.
- **Unit:**
  - no capabilities; hardening as in the spec, section 4;
  - never `ProtectProc=invisible`, `ProcSubset=pid`, `PrivateNetwork`, or `PrivateUsers`;
  - `systemd-analyze security` exposure ≤ 2.5;
  - installed disabled.
- **Commits:** agent-repository commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Component docs are updated in the same change.
- **CI:** real systemd in a podman container (user decision, option 1). Actions are pinned to full SHAs, like the existing workflow.

## Review Focus

- **The sandbox hides other users' processes:** a rule that needs PID 1 (`'systemd' in facts['process.names']`) must match under the unit. Task 2 checks it.
- **An upgrade loses the edited configuration or state:** after the upgrade, `agent.toml` is byte-identical and the queue and identity files are still present. Task 3 checks it.
- **A service that crash-loops when the config is incomplete:** with the shipped template (no rule sets), the service fails and restarts only every 30 s. Task 2 checks for at most 3 starts in 60 s.
- **Uninstall deletes state:** `/var/lib/openvibes-agent` survives `dnf remove`. Task 3 checks it.
- **A token file readable by others:** the walkthrough and the test create it 0600 `openvibes_agent`, and the check asserts the mode. Task 4 covers it.

---

### Task 1 (MA0): Package files and static checks

**Files:**
- Create `packaging/rpm/{openvibes-agent.spec,openvibes-agent.service,openvibes-agent.sysusers,agent.toml}`.
- Create `scripts/{build-rpm.sh,check-rpm.sh}`.
- Create `docs/components/packaging.md`, and add it to the component index.

- [ ] **Step 1: RED.** Write `scripts/check-rpm.sh`, which must be run as root after install. It checks:
  - the user `openvibes_agent` exists;
  - the `agent.toml` mode and owner, `%config(noreplace)`, and the `/etc/openvibes-agent` mode;
  - `systemd-analyze verify`;
  - exposure ≤ 2.5, taken from `systemd-analyze security openvibes-agent.service | tail -1`;
  - the service is disabled;
  - the forbidden directives are absent from the unit;
  - `openvibes-agent` with no arguments prints the usage and exits 2.

  Run it in `podman run --rm fedora:44` with only `systemd` installed. Expected: `FAIL: no user openvibes_agent`.
- [ ] **Step 2: GREEN.** Write the unit (spec, section 4, with a comment on the directives left out), the sysusers line, the template (`state_dir`, `platform_ca_file`, and `enrollment_token_file` preset; everything else commented), the spec file (sections as in the platform's spec; `%post`, `%preun`, and `%postun_with_restart` macros; one changelog entry), and `build-rpm.sh` (`cargo build --release --locked -p openvibes-agent`, then `rpmbuild -bb` with `ov_version` from the workspace `Cargo.toml`). Build, install in the container, and run `check-rpm.sh`. Expected: `check-rpm: ok`. Record the measured exposure score in `packaging.md`.
- [ ] **Step 3: Commit** with the message `Package the agent as a hardened Fedora RPM (MA0)`.

### Task 2 (MA1): Under systemd — install and sandboxed local-only run

**Files:** create `scripts/systemd-test.sh`; update `docs/components/packaging.md`.

**Interfaces:** `scripts/systemd-test.sh [RPM_DIR]` builds the RPMs if `RPM_DIR` is unset. It starts `podman run -d --systemd=always --name ov-agent-test -v RPM_DIR:/rpms:Z fedora:44 /sbin/init` (after `dnf install systemd sqlite` in a derived image, or with a `podman exec` install step), then runs the steps below with `podman exec`, and removes the container on exit.

- [ ] **Step 1: RED.** In the script:
  1. Install the RPM and run `check-rpm.sh`.
  2. Generate a key and sign a rule set with `sign_bundle`, built on the host with `cargo build --release --example sign_bundle`. Three rules: `'systemd' in facts['process.names']` (PID 1 is root's, so the sandbox must not hide it), `facts['package.count'] >= 50`, and `facts['port.tcp.exposed.count'] >= 0` (the fact exists only if the ports collector ran).
  3. Write a local-only `agent.toml` into the container (no `platform_url`; `bundle_file` under `/etc/openvibes-agent`; trusted key).
  4. `systemctl enable --now openvibes-agent`.
  5. Wait up to 30 s for three pending findings in `/var/lib/openvibes-agent/queue.sqlite`, one per rule id (`CAST(body AS TEXT) LIKE`).
  6. Check the process owner is `openvibes_agent` and that `CapEff` in `/proc/$(systemctl show -p MainPID --value openvibes-agent)/status` is `0000000000000000`.
  7. Check the state directory is 0700 `openvibes_agent`.

  Before writing the unit changes, first run the script against a deliberately wrong unit (add `ProtectProc=invisible`). Expected: FAIL on the `systemd` rule. Remove it again.
- [ ] **Step 2: Crash-loop check.** With the shipped template (no `[[rule_sets]]`, so the agent refuses its configuration), start the service, wait 60 s, and count starts in `journalctl -u openvibes-agent | grep -c started`, or `NRestarts`. Expected: ≤ 3.
- [ ] **Step 3: GREEN.** The script prints `ok:` lines and `systemd-test: all checks passed`. Commit with the message `Test the packaged agent under systemd: sandboxed collection (MA1)`.

### Task 3 (MA2): Upgrade, downgrade, uninstall; agent CI job

**Files:** modify `scripts/systemd-test.sh`, `scripts/build-rpm.sh` (accept `OV_VERSION` to override the version for the test build), and `.github/workflows/ci.yml` (new job); update `workflow.md` and `docs/components/packaging.md`.

- [ ] **Step 1: RED.** Extend the script with the following steps, then run it. Expected: it fails at the first new step (`build-rpm.sh` ignores `OV_VERSION`).
  1. Build a 0.1.1 test RPM (`OV_VERSION=0.1.1 build-rpm.sh`).
  2. Record the SHA-256 of `agent.toml` (edited in Task 2) and the inode and size of `identity.sqlite` and `queue.sqlite`.
  3. `dnf -y upgrade /rpms/openvibes-agent-0.1.1*.rpm`. Check: `rpm -q` shows 0.1.1, the service is active with a new MainPID, the config hash is unchanged, and the queue still holds at least the three findings.
  4. `dnf -y downgrade /rpms/openvibes-agent-0.1.0*.rpm`. Check the same things with 0.1.0.
  5. `dnf -y remove openvibes-agent`. Check: the unit is gone, the state directory and queue are still there, and the edited config is kept as `agent.toml.rpmsave` or in place.
- [ ] **Step 2: GREEN.** Implement `OV_VERSION` and rerun. Expected: all checks pass.
- [ ] **Step 3: CI job.** Add a `packaging` job on `ubuntu-latest` that needs `lint`, fetches the protocol submodule the same way as the other jobs, installs the pinned toolchain and `rpm` (`sudo apt-get install -y rpm`), and runs `bash scripts/systemd-test.sh` with rootful `sudo podman` if rootless systemd fails on the runner. The ruling on that goes in the ledger. Document the job in `workflow.md`.
- [ ] **Step 4: Commit** with the message `Test upgrade, downgrade, uninstall; packaging CI job (MA2)`. Push and open a PR; wait for CI.

### Task 4 (MA3): Platform end to end under systemd

This task runs after the agent PR is merged, which needs the user's approval. It happens in the platform repository.

**Files:**
- Modify the platform's `Cargo.toml` (agent pin to the merge commit) and `Cargo.lock`, and `.github/workflows/ci.yml` (the fedora job also builds the agent RPM and uploads all RPMs; a new `systemd-e2e` job).
- Create `scripts/systemd-e2e.sh`.
- Update `docs/components/packaging.md` ("Trying the whole system") and `docs/components/README.md`.

- [ ] **Step 1: RED.** Write `scripts/systemd-e2e.sh RPM_DIR`. It uses the same kind of container as the agent's test and scripts the walkthrough:
  1. `dnf install postgresql-server` plus the RPMs.
  2. `postgresql-setup --initdb` and start it.
  3. The documented role and database setup.
  4. `openvibes-admin migrate` and the CA steps.
  5. Install the ingest and distribution certificates.
  6. Start both services.
  7. Create a token, and trust and publish a bundle signed with `sign_bundle`.
  8. Write the agent's `platform-ca.crt`, the token file (0600 `openvibes_agent`, asserted), and `agent.toml` (`platform_url`, `distribution_url`, a rule set with no `bundle_file`).
  9. Enable the agent.

  It then waits up to 120 s for an active agent in `agents`, a 200 on `/v1/rule-bundle` in `journalctl -u openvibes-distribution`, and findings in PostgreSQL with `rule_set_id` set. Expected at first: FAIL because no agent RPM is available, then real failures until the steps are right.
- [ ] **Step 2: GREEN.** Bump the pin, build the agent RPM in the fedora job (check out the agent at the pinned revision with the same token mechanism as the fetch step, then run its `scripts/build-rpm.sh`), upload `target/rpm/RPMS/x86_64/*.rpm` as an artifact, and add the `systemd-e2e` job that downloads the artifact and runs the script with podman. Run the script locally first. Expected: `systemd-e2e: all checks passed`.
- [ ] **Step 3: Docs.** Write the walkthrough in `packaging.md`, "Trying the whole system", matching the script step for step. Record the decision `systemd in CI: option 1` in the workspace `decisions.md`.
- [ ] **Step 4: Commit** with the message `End to end under systemd: platform and agent RPMs (MA3)`, then open a PR and wait for CI.
