# eBPF Process Watcher — Design

**Status: design approved by the user on 2026-10-08 (three sections in
conversation). This written spec awaits the user's review. Next: the
implementation plan.**

## 1. Goal

Threat alarms (P14) must work out of the box, without changing the host's
audit policy. Today the agent learns about process starts from the kernel
audit system: the package loads an exec audit rule and, since 0.2.5,
comments out Fedora's `-a task,never` so the rule can fire. That works but
edits a system policy the admin chose, needs auditd running, and leaves
services started before the change unwatched until they restart (a task
created under `task,never` never gets an audit context).

The agent will watch process starts itself with an eBPF program, and keep
the audit reader as a fallback for kernels where eBPF cannot run.

Done when:

1. On a kernel ≥ 5.8 with BTF, alarms fire for process starts without any
   audit rule, with `-a task,never` left in place and auditd stopped, and
   for children of services that were running before the agent started.
2. Where eBPF cannot run, the agent uses the audit reader as today, and
   says so in health.
3. The package edits audit rules only on hosts that will use the fallback;
   upgrading an eBPF-capable host from 0.2.5 restores the `task,never`
   lines 0.2.5 commented out and removes the agent's exec audit rule.
4. The console shows, per host, whether alarms are on and from which
   source, and when they are off, why and the one command that fixes it.
5. Rules are unchanged: every existing `process_event` rule matches the
   same events.

Out of scope: event kinds other than process starts (§8 lists them),
Windows and macOS, restarting services or rebooting on the user's behalf
(never done).

## 2. Decisions (user, 2026-10-08)

- eBPF is the default source; audit is the fallback (not a user choice).
- The package edits audit rules only for fallback hosts, decided at
  install from the kernel (BTF present, kernel ≥ 5.8). The running agent
  never changes system policy.
- The in-kernel program is its own crate, `openvibes-agent-ebpf`, written
  in Rust with `aya-ebpf`, outside the workspace's `forbid(unsafe_code)`:
  reading kernel and process memory needs `unsafe`, and the kernel
  verifier checks every access before the program runs. Every other crate
  keeps the ban. The agent side uses `aya` (safe Rust, no C, no clang at
  runtime).
- Never restart services or reboot on the user's behalf.

## 3. How it works

### 3.1 Kernel side (`openvibes-agent-ebpf`)

One program on the `sched/sched_process_exec` tracepoint, attached as a
BTF tracepoint (`tp_btf`) so only the `bpf()` syscall is needed. It fires
once per successful exec, after the new image is loaded, and writes one
record to a ring buffer (`BPF_MAP_TYPE_RINGBUF`, 256 KiB):

- `pid` (tgid), parent `tgid` (`real_parent`), real and effective uid;
- the executed file's path (the tracepoint's `filename`);
- the arguments, read from the new process's memory (`mm->arg_start` ..
  `arg_end`) up to the agent's existing per-event limit
  (`EVENT_ARG_BYTES`), with a truncated flag beyond it;
- the kernel time of the event.

No working directory: the tracepoint has no cheap path for it; the field
stays optional as it is for audit events without one. CO-RE through BTF
makes one build run on every supported kernel. The object is built for the
BPF target and embedded in the agent binary (`include_bytes!`); nothing
extra is installed. A ring buffer that is full drops the record and counts
it (kernel side), reported like today's audit socket overflows.

### 3.2 Agent side

A new `ebpf` reader in `openvibes-collectors/src/process_events/` beside
the audit reader. It loads the embedded object, attaches it, reads the
ring buffer, and turns each record into the existing `ProcessStart`
(`records.rs`). The parent seed (`ProcessStart::parent`) is read from
`/proc` as today. Everything downstream — the process table, `process_event`
rules, masking, collapsing, the CEL budget, `AlarmBatch` delivery — is
unchanged.

### 3.3 Choosing the source

At start, when `process_events` is on: try eBPF; on failure, log the
reason once and use the audit reader. Failure reasons, each reported:
`no_btf`, `capability` (missing `CAP_BPF`/`CAP_PERFMON`), `lockdown`
(kernel lockdown in confidentiality mode), `lsm_denied` (a security module
refused `bpf()`), `verifier` (the kernel refused the program), `other`.

If the fallback then finds no exec audit rule loaded (an eBPF-capable host
by the package's check, where eBPF still failed at runtime), alarms are
off and health says so (§5); the agent does not change audit policy.

A test-only configuration switch forces the audit path, for the fallback
tests.

## 4. Privileges and packaging

### 4.1 The systemd unit

- `AmbientCapabilities` and `CapabilityBoundingSet`: `CAP_AUDIT_READ`
  (fallback, as today) plus `CAP_BPF` and `CAP_PERFMON`.
- The unit denies `~@privileged`, which contains `bpf`; it allows `bpf`
  explicitly and nothing else from that group. `perf_event_open` (in
  `@debug`) stays blocked: the `tp_btf` attach does not use it.
- After the program is loaded and attached, the agent drops `CAP_BPF` and
  `CAP_PERFMON` from all its capability sets for good, before it reads
  platform input or starts its loops. The rest of the sandbox
  (`ProtectSystem=strict`, `NoNewPrivileges`, …) is unchanged.

### 4.2 `%post` on install and upgrade

eBPF host (`/sys/kernel/btf/vmlinux` exists and kernel ≥ 5.8):

- Load no audit rule and touch no audit setting.
- The exec audit rule ships as an unused template in
  `/usr/share/openvibes-agent/openvibes-agent.rules`, not in
  `/etc/audit/rules.d`.
- Upgrading from 0.2.5: remove `/etc/audit/rules.d/openvibes-agent.rules`
  (only if unchanged from what 0.2.5 shipped; an edited copy is left and
  reported), and restore every line 0.2.5 commented out with the marker
  `# disabled by openvibes-agent (exec alarms need it off): `, then reload
  the rules when auditd runs. The admin's policy is back as it was.

Fallback host: today's behaviour — install the exec rule into
`rules.d`, comment out `-a task,never`, load the rules;
`manage_audit_rules = false` still opts out.

### 4.3 The fallback script

`/usr/libexec/openvibes-agent/audit-fallback` (root, run by the admin):
does what `%post` does for a fallback host. The console names it when an
eBPF-capable host's eBPF failed at runtime (§3.3).

## 5. Health, protocol, console

Protocol first (`openvibes-protocol`), then agent and platform:

- `health.alarms.source`: `ebpf` | `audit` | `none`.
- `health.alarms` reasons gain `ebpf_unavailable` with a `detail`
  (§3.3's list) and `audit_not_set_up`.
- Additive only; a platform treats a missing `source` (older agents) as
  `audit`.

Console, host page (the agent health panel): "Threat alarms: on (eBPF)",
"on (audit)", or "off — why — the fix" (for example "this kernel has no
BTF: run `sudo /usr/libexec/openvibes-agent/audit-fallback` on the host").
The Hosts list badges only hosts whose alarms are off (quiet by default).

## 6. Cost

- Memory: the 256 KiB ring buffer plus the embedded object; the agent's
  17 MB RSS budget (decisions.md, "Light agents") is rechecked.
- CPU: a few microseconds in the kernel per exec, and no auditd disk write
  per program start on eBPF hosts.
- Gate: the existing "Alarms cost (packaged binary)" CI job measures the
  eBPF path; it must use no more CPU than the audit path.

## 7. Testing

- Unit: decoding ring-buffer records into `ProcessStart` (argument cut,
  empty argv, long paths); the source choice for every failure reason;
  the `%post` logic, including the upgrade from 0.2.5 (marked lines
  restored, the unchanged exec rule removed, an edited one kept).
- Real kernel (CI "Alarms on a real kernel", a VM runner): with eBPF and
  `-a task,never` in place, a short-lived `sh -c` from a web-server-like
  parent raises `alarm.web_server.shell`; the same with auditd stopped.
- Lab (`openvibes-lab`): eBPF and an alarm after install on Fedora, Debian,
  Ubuntu, AlmaLinux and Arch; forced fallback (the test switch) and a
  no-BTF case raise alarms through audit after `audit-fallback`.
- Cost and footprint: the "Alarms cost" job and the lab's agent sweep.

## 8. Later: more event kinds

eBPF can watch far more than process starts. Each of these would be a new
event kind with its own named fields in the rule language; rules stay CEL
over those fields, and nobody writes eBPF to make a rule:

- network connections (`connect`/`accept`): "nginx connected to an
  unusual port", "a shell opened an outbound connection";
- file opens and writes on sensitive paths: `/etc/shadow`, SSH keys, cron;
- privilege changes: `setuid`, capability gains, `ptrace` of another
  process;
- kernel module loads;
- DNS lookups per process.

None of these is in this design; each needs its own spec (protocol event
kind and fields, masking, cost gate).

## 9. Order of work

Each step is a pull request with green CI:

1. Protocol: `health.alarms.source` and the reasons (§5).
2. Agent: the eBPF crate, the reader, the source choice, dropping the
   capabilities.
3. Packaging: the unit (§4.1), `%post` (§4.2), `audit-fallback` (§4.3).
4. Platform: store and show the source and reasons.
5. Lab: the eBPF and fallback checks (§7).
