# eBPF Process Watcher, Plan A (the watcher) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The agent learns process starts from its own eBPF program (audit as fallback) and reports the source in health, so alarms fire with `-a task,never` in place and auditd stopped.

**Architecture:** A new no-`std` crate `openvibes-agent-ebpf` holds one `tp_btf` program on `sched_process_exec` that writes exec records to a ring buffer. `openvibes-collectors` embeds the compiled object, reads the running kernel's BTF for the struct field offsets the program needs (Rust eBPF has no CO-RE relocations), loads and attaches it with `aya`, and turns records into the existing `ProcessStart`. The shared half of today's audit reader (parent lookup, recent-exec set, non-blocking send, drop counts) is split out so both sources feed the alarm engine the same way.

**Tech Stack:** Rust 1.95 (workspace, stable), nightly + `bpf-linker` 0.11 (eBPF crate only), `aya` 0.14, `aya-ebpf` 0.2, `aya-build` 0.2, `caps` 0.5, JSON Schema (protocol).

**Spec:** `docs/specs/2026-10-08-ebpf-process-watcher-design.md` (read it first). This is Plan A of three: Plan B is packaging (`%post`, `audit-fallback`), Plan C the platform display and lab checks. The unit file's capabilities and syscall filter (spec §4.1) are in this plan because the watcher cannot run without them.

## Global Constraints

- Kernel floor for eBPF: ≥ 5.8 with `/sys/kernel/btf/vmlinux`; anything else uses the audit reader.
- Ring buffer: `BPF_MAP_TYPE_RINGBUF`, 256 KiB.
- Arguments captured up to `EVENT_ARG_BYTES` (the existing constant in `process_events/records.rs`), truncated flag beyond.
- Every crate except `openvibes-agent-ebpf` keeps `forbid(unsafe_code)`; the gate's `-F unsafe-code` covers the workspace, and the eBPF crate is not a workspace member.
- The agent never changes system policy (audit rules); it never restarts services or reboots.
- `health.alarms.source` ∈ `ebpf | audit | none`; fallback detail ∈ `no_btf | capability | lockdown | lsm_denied | verifier | other`; additive wire change only, made in `openvibes-protocol` first.
- After load and attach, `CAP_BPF` and `CAP_PERFMON` are dropped from every capability set, before platform input is read.
- The unit allows the `bpf` syscall explicitly (it denies `~@privileged`); `perf_event_open` stays blocked.
- Cost gate: the eBPF path uses no more CPU than the audit path ("Alarms cost" job); RSS stays within the 17 MB budget.
- Commits end with `Co-Authored-By: Claude <noreply@anthropic.com>`; PRs only after the local gate in the workspace `testing.md`.

## Review Focus

1. **A kernel whose BTF lacks a field the program needs** (renamed or moved member, e.g. a future `task_struct` change) — the agent must fall back to audit with detail `other` and a log line naming the field, not load a program with a wrong offset (Task 6 test `missing_field_falls_back`).
2. **Ring buffer full under an exec storm** — records are dropped in the kernel and counted into `Drops::overflow`, never block the exec (Task 5 kernel counter, Task 6 test `ring_overflow_counts_as_overflow`).
3. **Arguments longer than `EVENT_ARG_BYTES`, empty argv, a path at the max length** — decoded without panics, truncated flag set (Task 6 decode tests).
4. **Capabilities still held after attach** (a failed drop) — the agent must not go on with `CAP_BPF`: it logs, drops the eBPF source and uses audit (Task 8 test `drop_failure_means_no_ebpf`).
5. **An older platform that rejects unknown health fields** — the new fields are optional and additive; protocol fixtures prove an agent heartbeat without them is still valid and one with them validates (Task 2 fixtures).

---

## File structure

```
openvibes-protocol/
  schemas/v1/heartbeat.schema.json            + alarms.source, alarms.fallback
  fixtures/v1/heartbeat/valid-alarms-source-ebpf.json      (new)
  fixtures/v1/heartbeat/valid-alarms-fallback.json         (new)
  fixtures/v1/heartbeat/invalid-alarms-source-unknown.json (new)
  spec/contracts-v1.md, PLAN.md                            text

openvibes-agent/
  ebpf/openvibes-agent-ebpf/        new crate, NOT a workspace member
    Cargo.toml, rust-toolchain.toml (nightly), src/main.rs (the program)
    src/record.rs                   the record layout shared by both sides
  crates/openvibes-core/src/health.rs          AlarmSource, AlarmFallback, fields
  crates/openvibes-collectors/
    build.rs                        aya-build: compile and embed the object (feature "ebpf")
    src/process_events/forward.rs   shared half of the reader (split from reader.rs)
    src/process_events/ebpf.rs      load, offsets, attach, ring buffer -> ProcessStart
    src/process_events/btf.rs       field offsets from /sys/kernel/btf/vmlinux
    src/process_events/choose.rs    try eBPF, else audit; reasons
  crates/openvibes-agent/src/alarms/thread.rs   use choose.rs; health source
  crates/openvibes-agent/src/caps.rs            drop CAP_BPF/CAP_PERFMON
  packaging/rpm/openvibes-agent.service         capabilities, bpf syscall
  .github/workflows/ci.yml                      nightly + bpf-linker, eBPF kernel job
  scripts/alarms-kernel-e2e.sh                  an eBPF run with task,never and auditd stopped
  docs/components/*.md                          collectors, agent, packaging pages
```

---

### Task 1: Spike — BTF field offsets for a Rust eBPF program (throwaway)

The one thing this plan cannot assume: that a Rust eBPF program can read `task_struct`/`mm_struct`/`cred` fields correctly on every target kernel with offsets the agent reads from the running kernel's BTF and passes as globals. Prove it before building on it. Output is a yes/no and the API calls that work; the code is thrown away.

**Files:** a scratch branch `spike-ebpf-offsets` in a worktree; nothing merged.

- [ ] **Step 1: Toolchain**

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --version 0.11.1 --locked
```

- [ ] **Step 2: A minimal program** (`ebpf/spike/src/main.rs`, `#![no_std] #![no_main]`): a `#[btf_tracepoint(function = "sched_process_exec")]` that reads `bpf_get_current_task()`, then with `bpf_probe_read_kernel` at offsets taken from globals `TASK_REAL_PARENT`, `TASK_TGID`, `TASK_MM`, `TASK_CRED`, `MM_ARG_START`, `MM_ARG_END`, `CRED_UID`, `CRED_EUID`, `BINPRM_FILENAME` (`#[no_mangle] static` read with `core::ptr::read_volatile`, set by the loader via `EbpfLoader::set_global`), and writes `{pid, ppid, euid, arg_start, arg_end}` to a `RingBuf`.

- [ ] **Step 3: The loader's offsets.** Parse `/sys/kernel/btf/vmlinux` and find each struct member's byte offset. Try in this order and record which works with aya 0.14 / aya-obj: (a) `aya_obj::btf::Btf::parse(&bytes, Endianness::default())`, `id_by_type_name_kind("task_struct", BtfKind::Struct)`, `type_by_id(id)`, iterate the struct's members, `string_at(member.name_offset)`, bit offset ÷ 8; (b) if aya-obj keeps members private, the `btf` crate's parser or a 150-line BTF reader of our own (the format is simple: header, type section, string section; `docs.kernel.org/bpf/btf.html`). `cred.euid` is a `kuid_t` struct wrapping `val`: add its member offset (0).

- [ ] **Step 4: Run on every lab system**

```bash
cd ~/Projects/OpenVIBES/openvibes-lab
./lab up --bare fedora debian ubuntu alma arch
for n in fedora debian ubuntu alma arch; do ./lab ssh $n uname -r; done
# copy the spike binary to each, run it as root, then run: sh -c 'sleep 1'
```

Expected on each: the spike prints records whose `pid`/`ppid` match `ps -o pid,ppid` for the test `sh`, `euid` matches `id -u`, and reading `arg_end - arg_start` bytes from `/proc/<pid>/cmdline` agrees with the args. Kernels: Fedora 44 (7.x), Debian 13 (6.12), Ubuntu 24.04 (6.8), Alma 10 (6.12), Arch (latest).

- [ ] **Step 5: Decide.** All five agree → record in the workspace `decisions.md` ("eBPF field offsets from BTF at load time", with the API used) and go on to Task 2. Any fails, or the verifier refuses on one → STOP and bring the evidence to the user before writing more code (options then: C for the kernel side with libbpf CO-RE, or fields from `/proc` with their known race).

---

### Task 2: Protocol — `health.alarms.source` and `fallback`

**Files:**
- Modify: `openvibes-protocol/schemas/v1/heartbeat.schema.json` (the `alarms` object)
- Create: `fixtures/v1/heartbeat/valid-alarms-source-ebpf.json`, `valid-alarms-fallback.json`, `invalid-alarms-source-unknown.json`
- Modify: `spec/contracts-v1.md` (health section, P14), `PLAN.md` (P14 list)

**Interfaces:**
- Produces: `alarms.source` (string enum `ebpf|audit|none`, optional), `alarms.fallback` (optional object `{detail: enum no_btf|capability|lockdown|lsm_denied|verifier|other, audit_rule_loaded: boolean}`).

- [ ] **Step 1: Fixtures first.** Copy `valid-alarms-health-budget-cut.json` to the two valid names; in the first set `"source": "ebpf"` in `health.alarms`; in the second `"source": "audit", "fallback": {"detail": "no_btf", "audit_rule_loaded": true}`. Copy it to `invalid-alarms-source-unknown.json` with `"source": "kprobe"`.

- [ ] **Step 2: Run the validator — the valid ones must fail now** (`additionalProperties` is closed on `alarms`? If it is open, the invalid one passes instead; either way one fixture fails):

Run: `.venv/bin/python tools/validate.py`
Expected: FAIL naming one of the three new fixtures.

- [ ] **Step 3: Schema.** Inside `health.alarms.properties` add:

```json
"source": {
  "type": "string",
  "enum": ["ebpf", "audit", "none"],
  "description": "Optional: where process starts come from. Missing means audit (agents before the eBPF watcher)."
},
"fallback": {
  "type": "object",
  "description": "Optional: present when eBPF could not be used.",
  "additionalProperties": false,
  "required": ["detail", "audit_rule_loaded"],
  "properties": {
    "detail": {"type": "string", "enum": ["no_btf", "capability", "lockdown", "lsm_denied", "verifier", "other"]},
    "audit_rule_loaded": {"type": "boolean", "description": "false: alarms are off until the audit fallback is set up."}
  }
}
```

and, if `alarms` has no `"additionalProperties": false`, add it (unknown keys there are then errors, which is what the invalid fixture checks; verify no existing valid fixture breaks).

- [ ] **Step 4: Validate** — Run: `.venv/bin/python tools/validate.py` — Expected: PASS, every fixture.

- [ ] **Step 5: Text.** `spec/contracts-v1.md`: under the P14 health text, one paragraph: the two fields, "missing `source` means `audit`", `source: none` with `fallback.audit_rule_loaded: false` means alarms are off. `PLAN.md` P14: `- [ ] eBPF process watcher: health.alarms.source and fallback (spec openvibes-agent docs/specs/2026-10-08-ebpf-process-watcher-design.md)`.

- [ ] **Step 6: Commit, PR in `openvibes-protocol`** (branch `alarms-source`), CI green, merged before Task 3 pins it.

```bash
git add schemas/v1/heartbeat.schema.json fixtures/v1/heartbeat spec/contracts-v1.md PLAN.md
git commit -m "health.alarms: source and fallback for the eBPF watcher"
```

---

### Task 3: Core types — `AlarmSource`, `AlarmFallback`

**Files:**
- Modify: `crates/openvibes-core/src/health.rs:47-72`
- Modify: `protocol` submodule pointer (to the merge of Task 2)
- Test: the core crate's protocol fixture tests (find them: `grep -rn 'fixtures/v1/heartbeat' crates/openvibes-core`)

**Interfaces:**
- Produces (in `openvibes_core`):

```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlarmSource { Ebpf, Audit, None }

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackDetail { NoBtf, Capability, Lockdown, LsmDenied, Verifier, Other }

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AlarmFallback { pub detail: FallbackDetail, pub audit_rule_loaded: bool }
```

and on `AlarmHealth`: `#[serde(default, skip_serializing_if = "Option::is_none")] pub source: Option<AlarmSource>,` and the same for `pub fallback: Option<AlarmFallback>`.

- [ ] **Step 1: Pin the protocol submodule** to Task 2's merge: `git -C protocol fetch && git -C protocol checkout <sha> && git add protocol`.

- [ ] **Step 2: Failing test** in `health.rs`'s tests (or the existing fixture test file):

```rust
#[test]
fn alarm_health_round_trips_source_and_fallback() {
    let json = r#"{"collector":"ok","events_dropped_total":0,"alarms_dropped_total":0,"pending":0,
        "platform_unsupported":false,"rules_accepted":5,"rules_refused":0,"rules_without_prefilter":0,
        "source":"audit","fallback":{"detail":"no_btf","audit_rule_loaded":true}}"#;
    let health: AlarmHealth = serde_json::from_str(json).unwrap();
    assert_eq!(health.source, Some(AlarmSource::Audit));
    assert_eq!(health.fallback, Some(AlarmFallback { detail: FallbackDetail::NoBtf, audit_rule_loaded: true }));
    let back: serde_json::Value = serde_json::to_value(&health).unwrap();
    assert_eq!(back["source"], "audit");
}

#[test]
fn alarm_health_without_source_still_parses_and_omits_it() {
    let json = r#"{"collector":"ok","events_dropped_total":0,"alarms_dropped_total":0,"pending":0,
        "platform_unsupported":false,"rules_accepted":0,"rules_refused":0,"rules_without_prefilter":0}"#;
    let health: AlarmHealth = serde_json::from_str(json).unwrap();
    assert_eq!(health.source, None);
    assert!(serde_json::to_value(&health).unwrap().get("source").is_none());
}
```

- [ ] **Step 3: Run** `cargo test -p openvibes-core alarm_health_` — Expected: FAIL (no field `source`).
- [ ] **Step 4: Implement** the types and fields above; fix every `AlarmHealth { .. }` literal the compiler names (`source: None, fallback: None`).
- [ ] **Step 5: Run** `cargo test -p openvibes-core` — Expected: PASS, including the fixture tests over the new `valid-alarms-*` files.
- [ ] **Step 6: Commit** `git commit -m "core: AlarmHealth source and fallback (protocol <sha>)"`

---

### Task 4: Collectors — split the reader's shared half

No behaviour change: the audit path keeps every test green.

**Files:**
- Create: `crates/openvibes-collectors/src/process_events/forward.rs`
- Modify: `crates/openvibes-collectors/src/process_events/reader.rs` (keep `Source`, `Received`, audit joining), `mod.rs:19-27` (exports)
- Test: `crates/openvibes-collectors/src/process_events/tests.rs`

**Interfaces:**
- Produces:

```rust
/// One step of a source of process starts (audit joined, or eBPF records).
pub enum Next { Start(ProcessStart), Lost(u64), Unfinished(u64), Idle, Closed }

/// Anything that yields process starts.
pub trait StartSource: Send { fn next(&mut self) -> Next; }

/// Starts the forwarding thread `name`: parent lookup for unknown parents,
/// the recent-exec set, try_send to the engine, drop counting.
pub fn spawn_forwarder<S: StartSource + 'static>(
    name: &str, source: S, tx: SyncSender<Box<ProcessStart>>,
    dropped: Arc<Drops>, lookup: fn(u32) -> Option<Seeded>,
) -> std::io::Result<JoinHandle<()>>;

/// Today's audit path as a StartSource (Source + Joiner).
pub struct AuditStarts<S: Source> { .. }
impl<S: Source> AuditStarts<S> { pub fn new(source: S) -> Self; }
```

`spawn_reader(source, tx, dropped, lookup)` stays as a thin wrapper: `spawn_forwarder("audit-reader", AuditStarts::new(source), tx, dropped, lookup)`.

- [ ] **Step 1: Failing test** — a `StartSource` that yields two starts and closes reaches the channel, and a `Lost(3)` counts as overflow:

```rust
struct Scripted(std::vec::IntoIter<Next>);
impl StartSource for Scripted { fn next(&mut self) -> Next { self.0.next().unwrap_or(Next::Closed) } }

#[test]
fn forwarder_sends_starts_and_counts_losses() {
    let (tx, rx) = std::sync::mpsc::sync_channel(8);
    let drops = Arc::new(Drops::default());
    let a = test_start(100, 1); let b = test_start(101, 100);
    let src = Scripted(vec![Next::Start(a), Next::Lost(3), Next::Start(b)].into_iter());
    spawn_forwarder("t", src, tx, Arc::clone(&drops), |_| None).unwrap().join().unwrap();
    let got: Vec<u32> = rx.try_iter().map(|s| s.pid).collect();
    assert_eq!(got, [100, 101]);
    assert_eq!(drops.overflow.load(Ordering::Relaxed), 3);
}
```

(`test_start(pid, ppid)` builds a `ProcessStart` with fixed fields; add it to `tests.rs` if no such helper exists.)

- [ ] **Step 2: Run** `cargo test -p openvibes-collectors forwarder_` — Expected: FAIL (`spawn_forwarder` not found).
- [ ] **Step 3: Implement.** Move the loop body of `spawn_reader` (`reader.rs:73-125`) into `spawn_forwarder` matching on `Next`: `Start` → the existing parent-lookup/recent/try_send block; `Lost(n)` → `overflow += n`; `Unfinished(n)` → `unfinished += n`; `Idle` → nothing; `Closed` → return. `AuditStarts::next` wraps `source.recv` + `joiner.push` + `joiner.expire(now)` and returns `Unfinished(expired)` when the joiner expired events, `Start` when a start completed, `Lost(1)` on `Received::Lost`.
- [ ] **Step 4: Run** `cargo test -p openvibes-collectors` and `cargo test -p openvibes-agent --test alarms` — Expected: PASS (every existing audit test unchanged).
- [ ] **Step 5: Commit** `git commit -m "collectors: split the process-start forwarder from the audit reader"`

---

### Task 5: The eBPF crate and its build

**Files:**
- Create: `ebpf/openvibes-agent-ebpf/Cargo.toml`, `ebpf/openvibes-agent-ebpf/rust-toolchain.toml`, `ebpf/openvibes-agent-ebpf/src/main.rs`, `ebpf/openvibes-agent-ebpf/src/record.rs`
- Create: `crates/openvibes-collectors/build.rs`
- Modify: `crates/openvibes-collectors/Cargo.toml` (feature `ebpf`, build-dependency `aya-build`), root `Cargo.toml` (`exclude = ["ebpf"]`)
- Modify: `.github/workflows/ci.yml` (every job that builds with `--all-features`: install nightly + `bpf-linker`), `docs/components/` (new `openvibes-agent-ebpf.md`, index line)

**Interfaces:**
- Produces: `record.rs`, included by both sides (`#[path]` include from the collectors crate):

```rust
pub const ARG_BYTES: usize = 4096; // must equal EVENT_ARG_BYTES; a test in Task 6 asserts it
pub const PATH_BYTES: usize = 256;
#[repr(C)]
pub struct ExecRecord {
    pub pid: u32, pub ppid: u32, pub uid: u32, pub euid: u32,
    pub ktime_ns: u64,
    pub path_len: u16, pub args_len: u16, pub args_truncated: u8, pub _pad: [u8; 3],
    pub path: [u8; PATH_BYTES],
    pub args: [u8; ARG_BYTES],   // NUL-separated, as /proc/<pid>/cmdline
}
```

- Globals the loader sets (names exact): `TASK_REAL_PARENT`, `TASK_TGID`, `TASK_MM`, `TASK_CRED`, `MM_ARG_START`, `MM_ARG_END`, `CRED_UID`, `CRED_EUID`, `BINPRM_FILENAME` (all `u32` byte offsets); map names: `EVENTS` (RingBuf, 256 KiB), `DROPPED` (`Array<u64>`, one slot).
- Embedded bytes: `openvibes_collectors::process_events::ebpf::OBJECT: &[u8]` (feature `ebpf`).

- [ ] **Step 1: The crate.** `Cargo.toml`:

```toml
[package]
name = "openvibes-agent-ebpf"
version = "0.1.0"
edition = "2024"
license = "MIT"
publish = false

[dependencies]
aya-ebpf = "0.2.1"

[[bin]]
name = "openvibes-agent-ebpf"
path = "src/main.rs"

[profile.release]
panic = "abort"
debug = 2
```

`rust-toolchain.toml`: `[toolchain] channel = "nightly-2026-10-01"` with `components = ["rust-src"]` (pin the date; bump deliberately).

- [ ] **Step 2: The program** (`src/main.rs`). With the API Task 1 proved:

```rust
#![no_std]
#![no_main]
// Kernel-side eBPF: reads kernel and process memory through BPF helpers, which
// is unsafe by nature; the kernel verifier checks every access before it runs.
// Outside the agent workspace's forbid(unsafe_code) by decision (2026-10-08).

mod record;
use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC, helpers::{bpf_get_current_task, bpf_ktime_get_ns,
    bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_buf},
    macros::{btf_tracepoint, map}, maps::{Array, RingBuf}, programs::BtfTracePointContext,
};
use record::{ExecRecord, ARG_BYTES, PATH_BYTES};

#[map] static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
#[map] static DROPPED: Array<u64> = Array::with_max_entries(1, 0);

#[unsafe(no_mangle)] static TASK_REAL_PARENT: u32 = 0;
#[unsafe(no_mangle)] static TASK_TGID: u32 = 0;
#[unsafe(no_mangle)] static TASK_MM: u32 = 0;
#[unsafe(no_mangle)] static TASK_CRED: u32 = 0;
#[unsafe(no_mangle)] static MM_ARG_START: u32 = 0;
#[unsafe(no_mangle)] static MM_ARG_END: u32 = 0;
#[unsafe(no_mangle)] static CRED_UID: u32 = 0;
#[unsafe(no_mangle)] static CRED_EUID: u32 = 0;
#[unsafe(no_mangle)] static BINPRM_FILENAME: u32 = 0;

fn off(v: &u32) -> usize { unsafe { core::ptr::read_volatile(v) as usize } }

unsafe fn field<T: Copy>(base: *const u8, offset: usize) -> Result<T, i64> {
    unsafe { bpf_probe_read_kernel(base.add(offset) as *const T) }
}

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> i32 {
    match unsafe { record_exec(&ctx) } { Ok(()) => 0, Err(_) => 0 }
}

unsafe fn record_exec(ctx: &BtfTracePointContext) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<ExecRecord>(0) else {
        if let Some(n) = DROPPED.get_ptr_mut(0) { unsafe { *n += 1 }; }
        return Ok(());
    };
    let rec = entry.as_mut_ptr();
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let parent: *const u8 = unsafe { field(task, off(&TASK_REAL_PARENT))? };
    let mm: *const u8 = unsafe { field(task, off(&TASK_MM))? };
    let cred: *const u8 = unsafe { field(task, off(&TASK_CRED))? };
    let arg_start: u64 = unsafe { field(mm, off(&MM_ARG_START))? };
    let arg_end: u64 = unsafe { field(mm, off(&MM_ARG_END))? };
    unsafe {
        (*rec).pid = field(task, off(&TASK_TGID))?;
        (*rec).ppid = field(parent, off(&TASK_TGID))?;
        (*rec).uid = field(cred, off(&CRED_UID))?;
        (*rec).euid = field(cred, off(&CRED_EUID))?;
        (*rec).ktime_ns = bpf_ktime_get_ns();
        // sched_process_exec(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
        let bprm: *const u8 = ctx.arg(2);
        let name: *const u8 = field(bprm, off(&BINPRM_FILENAME))?;
        let path = bpf_probe_read_kernel_str_bytes(name, &mut (*rec).path).unwrap_or(&[]);
        (*rec).path_len = path.len().min(PATH_BYTES) as u16;
        let len = (arg_end.saturating_sub(arg_start) as usize).min(ARG_BYTES);
        (*rec).args_truncated = u8::from(arg_end.saturating_sub(arg_start) as usize > ARG_BYTES);
        (*rec).args_len = len as u16;
        let _ = bpf_probe_read_user_buf(arg_start as *const u8, &mut (*rec).args[..len]);
    }
    entry.submit(0);
    Ok(())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
```

The path comes from `bprm->filename` (one more offset, `BINPRM_FILENAME`, read in Task 1 alongside the others), bounded by `PATH_BYTES`. Task 1's spike must include it.

- [ ] **Step 3: Embed it.** `crates/openvibes-collectors/build.rs`, only with feature `ebpf`:

```rust
fn main() {
    #[cfg(feature = "ebpf")]
    {
        let package = aya_build::cargo_metadata::MetadataCommand::new()
            .manifest_path("../../ebpf/openvibes-agent-ebpf/Cargo.toml").no_deps().exec()
            .expect("eBPF crate metadata").packages.into_iter()
            .find(|p| p.name == "openvibes-agent-ebpf").expect("openvibes-agent-ebpf");
        aya_build::build_ebpf([package]).expect("build the eBPF program (needs nightly and bpf-linker)");
    }
}
```

and in `ebpf.rs`: `pub static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/openvibes-agent-ebpf"));`. Check `aya-build` 0.2's exact `build_ebpf` signature in its docs and adjust; the contract is "the object lands in `OUT_DIR`".

- [ ] **Step 4: Build.** Run: `cargo build -p openvibes-collectors --features ebpf` — Expected: builds; `llvm-objdump -h $(find target -name openvibes-agent-ebpf -path '*out*' | head -1)` lists sections `tp_btf/sched_process_exec` and `maps`.
- [ ] **Step 5: CI.** In each job that runs `--all-features`, after the toolchain step:

```yaml
      - name: eBPF build tools (nightly, bpf-linker)
        run: |
          rustup toolchain install nightly-2026-10-01 --component rust-src --profile minimal
          cargo install bpf-linker --version 0.11.1 --locked
```

Gate the Windows/macOS matrix entries out of the feature (`--features` there omits `ebpf`; the feature is Linux-only, `#[cfg(target_os = "linux")]` on the module).
- [ ] **Step 6: Commit** `git commit -m "eBPF exec program (openvibes-agent-ebpf), embedded with feature ebpf"`

---

### Task 6: The eBPF reader — offsets, load, decode

**Files:**
- Create: `crates/openvibes-collectors/src/process_events/btf.rs`, `.../ebpf.rs`
- Test: `crates/openvibes-collectors/src/process_events/ebpf_tests.rs` (`#[cfg(test)] mod`)

**Interfaces:**
- Consumes: `StartSource`, `Next` (Task 4); `OBJECT`, `ExecRecord`, globals and maps (Task 5).
- Produces:

```rust
pub struct Offsets { pub task_real_parent: u32, pub task_tgid: u32, pub task_mm: u32,
    pub task_cred: u32, pub mm_arg_start: u32, pub mm_arg_end: u32,
    pub cred_uid: u32, pub cred_euid: u32, pub binprm_filename: u32 }
/// From the running kernel's BTF; Err names the missing struct or field.
pub fn offsets_from_btf(btf: &[u8]) -> Result<Offsets, MissingField>;
pub struct MissingField(pub &'static str);

/// Decodes one ring-buffer record. None: shorter than ExecRecord.
pub fn decode(bytes: &[u8], now_unix_ms: i64) -> Option<ProcessStart>;

/// Loaded and attached program; a StartSource over its ring buffer.
pub struct EbpfStarts { .. }
pub fn open_ebpf() -> Result<EbpfStarts, EbpfError>;
pub enum EbpfError { NoBtf, MissingField(&'static str), Capability, Lockdown, LsmDenied, Verifier(String), Other(String) }
```

- [ ] **Step 1: Failing decode tests** (`ebpf_tests.rs`):

```rust
fn record(pid: u32, ppid: u32, path: &[u8], args: &[u8], truncated: bool) -> Vec<u8> {
    let mut r = ExecRecord { pid, ppid, uid: 33, euid: 0, ktime_ns: 1, path_len: path.len() as u16,
        args_len: args.len() as u16, args_truncated: u8::from(truncated), _pad: [0; 3],
        path: [0; PATH_BYTES], args: [0; ARG_BYTES] };
    r.path[..path.len()].copy_from_slice(path);
    r.args[..args.len()].copy_from_slice(args);
    as_bytes(&r).to_vec()   // tiny safe helper: zerocopy or bytemuck derive on ExecRecord
}

#[test] fn decodes_exe_args_and_ids() {
    let s = decode(&record(10, 1, b"/usr/bin/sh", b"sh\0-c\0sleep 1\0", false), 5).unwrap();
    assert_eq!((s.pid, s.ppid, s.uid, s.euid), (10, 1, 33, 0));
    assert_eq!(s.exe, b"/usr/bin/sh");
    assert_eq!(s.args, [b"sh".to_vec(), b"-c".to_vec(), b"sleep 1".to_vec()]);
    assert!(!s.args_truncated);
}
#[test] fn empty_argv_is_no_args() {
    assert!(decode(&record(10, 1, b"/x", b"", false), 5).unwrap().args.is_empty());
}
#[test] fn truncated_args_keep_the_flag() {
    let long = vec![b'a'; ARG_BYTES];
    assert!(decode(&record(10, 1, b"/x", &long, true), 5).unwrap().args_truncated);
}
#[test] fn lengths_beyond_the_arrays_are_clamped() {
    let mut b = record(10, 1, b"/x", b"a\0", false);
    b[24..26].copy_from_slice(&u16::MAX.to_ne_bytes()); // path_len
    assert!(decode(&b, 5).is_some());
}
#[test] fn short_records_are_refused() { assert!(decode(&[0; 8], 5).is_none()); }
#[test] fn arg_limit_matches_the_agent() { assert_eq!(ARG_BYTES, EVENT_ARG_BYTES); }
#[test] fn missing_field_falls_back() {
    // A BTF blob without task_struct (a fixture: tests/fixtures/btf-no-task.bin, made in
    // Step 3 by cutting the struct from a real vmlinux BTF) names the struct.
    assert_eq!(offsets_from_btf(include_bytes!("../../tests/fixtures/btf-no-task.bin")).err().unwrap().0, "task_struct");
}
#[test] fn ring_overflow_counts_as_overflow() {
    // EbpfStarts::next reports a grown DROPPED counter as Next::Lost(delta).
    assert!(matches!(lost_since(7, 10), Next::Lost(3)));
}
```

`decode` is pure; `lost_since(previous, current) -> Next` is the pure helper `EbpfStarts::next` uses for the `DROPPED` delta.

- [ ] **Step 2: Run** `cargo test -p openvibes-collectors --features ebpf ebpf_` — Expected: FAIL (functions missing).
- [ ] **Step 3: Implement** `decode` (clamp lengths to the arrays, split args on NUL dropping the trailing empty piece, `at_unix_ms` from `now_unix_ms`, `cwd: None`, `parent: None` — the forwarder fills it), `lost_since`, and `offsets_from_btf` with the API Task 1 proved. Make the `btf-no-task.bin` fixture the way the test comment says (a script under `scripts/` that writes it, committed with the fixture).
- [ ] **Step 4: Implement `open_ebpf`:** `/sys/kernel/btf/vmlinux` missing → `NoBtf`; read offsets (→ `MissingField`); `EbpfLoader::new()` with `set_global` for each offset; `load(OBJECT)`; `program_mut("sched_process_exec")` as `BtfTracePoint`, `load("sched_process_exec", &Btf::from_sys_fs()?)`, `attach()`; map errors: `EPERM` with `CAP_BPF` missing → `Capability`; `EPERM` with `/sys/kernel/security/lockdown` showing `[confidentiality]` → `Lockdown`; other `EPERM`/`EACCES` → `LsmDenied`; a verifier log → `Verifier(log head)`; else `Other`. `EbpfStarts::next` polls the ring buffer's fd for 200 ms (rustix `poll`), returns `Start(decode(..))`, `Lost(delta)` when `DROPPED` grew, `Idle` on timeout.
- [ ] **Step 5: Run** `cargo test -p openvibes-collectors --features ebpf` — Expected: PASS.
- [ ] **Step 6: Commit** `git commit -m "collectors: eBPF process starts (BTF offsets, ring buffer, decode)"`

---

### Task 7: Choosing the source, and health

**Files:**
- Create: `crates/openvibes-collectors/src/process_events/choose.rs`
- Modify: `crates/openvibes-agent/src/alarms/thread.rs:90-115` (`spawn`), `crates/openvibes-agent/src/config.rs` (test switch)
- Test: `crates/openvibes-agent/tests/alarms.rs`

**Interfaces:**
- Consumes: `open_ebpf`, `EbpfError` (Task 6), `open_audit_socket`, `AuditStarts` (Task 4), `AlarmSource`, `AlarmFallback`, `FallbackDetail` (Task 3).
- Produces:

```rust
pub struct Opened { pub source: AlarmSource, pub fallback: Option<AlarmFallback>,
                    pub starts: Option<Box<dyn StartSource>> }
/// eBPF first unless `force_audit`; on failure the audit socket. starts None: alarms off.
pub fn open_process_starts(force_audit: bool, audit_rule_loaded: fn() -> bool) -> Opened;
pub fn fallback_detail(error: &EbpfError) -> FallbackDetail;
```

Config (test switch, documented as for tests): `process_events_source = "audit"` in `agent.toml` forces the audit reader; any other value is a config error; absent = eBPF first.

- [ ] **Step 1: Failing tests:**

```rust
#[test] fn every_ebpf_error_has_a_detail() {
    use openvibes_collectors::process_events::{EbpfError::*, fallback_detail};
    assert_eq!(fallback_detail(&NoBtf), FallbackDetail::NoBtf);
    assert_eq!(fallback_detail(&MissingField("task_struct")), FallbackDetail::Other);
    assert_eq!(fallback_detail(&Capability), FallbackDetail::Capability);
    assert_eq!(fallback_detail(&Lockdown), FallbackDetail::Lockdown);
    assert_eq!(fallback_detail(&LsmDenied), FallbackDetail::LsmDenied);
    assert_eq!(fallback_detail(&Verifier("x".into())), FallbackDetail::Verifier);
}
#[test] fn forced_audit_reports_audit_without_fallback() {
    let opened = open_process_starts(true, || true);
    assert_eq!(opened.source, AlarmSource::Audit);   // or None where the test host has no audit socket
    assert!(opened.fallback.is_none());
}
#[test] fn config_source_switch_accepts_only_audit() {
    assert!(parse_config("process_events_source = \"audit\"\n").is_ok());
    assert!(parse_config("process_events_source = \"kprobe\"\n").is_err());
}
```

(`parse_config` is whatever the config tests already use to load a TOML string; reuse it.)

- [ ] **Step 2: Run** them — Expected: FAIL.
- [ ] **Step 3: Implement.** `open_process_starts`: unless forced, `open_ebpf()` → `Ok` → `{Ebpf, None, Some(Box::new(starts))}`, log "reading process starts with eBPF"; `Err(e)` → log once "eBPF unavailable (<detail>: <message>); reading process starts from kernel audit", then `open_audit_socket()`: `Ok` → `{Audit, Some({detail, audit_rule_loaded: audit_rule_loaded()}), Some(AuditStarts)}`; `Err` → `{None, Some({detail, false}), None}`. `audit_rule_loaded` checks the agent's exec key is loaded: today's thread already learns this from the first keyed record; use `false` until the first keyed record arrives and update the shared health then (the same place that sets `collector` to `ok`). In `thread.rs::spawn` replace `open_audit_socket()` with `open_process_starts(config.force_audit, ..)`, store `source`/`fallback` in the shared `AlarmHealth`, and start `spawn_forwarder` with the chosen name (`"ebpf-reader"` or `"audit-reader"`).
- [ ] **Step 4: Run** `cargo test -p openvibes-agent` — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "agent: eBPF first, audit fallback; health reports the source"`

---

### Task 8: Drop the eBPF capabilities after attach

**Files:**
- Create: `crates/openvibes-agent/src/caps.rs`
- Modify: `crates/openvibes-agent/src/alarms/thread.rs` (after `open_process_starts`), `crates/openvibes-agent/Cargo.toml` (`caps = "0.5.6"`, Linux only)

**Interfaces:**
- Produces: `pub fn drop_ebpf_caps() -> Result<(), String>` — removes `CAP_BPF` and `CAP_PERFMON` from the effective, permitted, inheritable, ambient and bounding sets of the process (all threads: call it before any other thread exists, or use `caps::clear`/`drop` per set; the agent's other threads start after alarms are set up — check the order in `service.rs::open` and move the call first if needed).

- [ ] **Step 1: Failing test** (runs as an ordinary user, who holds neither capability — so it checks the function's postcondition and that it does not error):

```rust
#[test]
fn after_the_drop_no_ebpf_capability_is_held() {
    drop_ebpf_caps().unwrap();
    for set in [caps::CapSet::Effective, caps::CapSet::Permitted, caps::CapSet::Ambient] {
        assert!(!caps::has_cap(None, set, caps::Capability::CAP_BPF).unwrap());
        assert!(!caps::has_cap(None, set, caps::Capability::CAP_PERFMON).unwrap());
    }
}
#[test]
fn drop_failure_means_no_ebpf() {
    // With a failing drop, the chosen source is downgraded: eBPF is dropped, audit opened.
    assert_eq!(after_drop(Err("x".into()), AlarmSource::Ebpf), AlarmSource::Audit);
    assert_eq!(after_drop(Ok(()), AlarmSource::Ebpf), AlarmSource::Ebpf);
}
```

(`after_drop` is the pure decision `thread.rs` uses.)

- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement** `drop_ebpf_caps` with the `caps` crate and `after_drop`; in `thread.rs`, when the source is eBPF call it at once; on `Err`, log it, drop the `EbpfStarts` (detaches the program) and reopen with `open_process_starts(true, ..)`.
- [ ] **Step 4: Run** `cargo test -p openvibes-agent caps` and the whole crate — Expected: PASS. The real proof (capabilities gone from `/proc/<pid>/status` under the unit) is in Task 9.
- [ ] **Step 5: Commit** `git commit -m "agent: drop CAP_BPF and CAP_PERFMON once the eBPF program is attached"`

---

### Task 9: The unit, the real-kernel job, the cost gate

**Files:**
- Modify: `packaging/rpm/openvibes-agent.service`, `scripts/check-unit.sh`, `scripts/alarms-kernel-e2e.sh`, `scripts/alarms-cost.sh`, `.github/workflows/ci.yml`, `docs/components/packaging.md`, `docs/components/openvibes-agent.md`, `docs/components/openvibes-collectors.md` (or the page that covers process events)

- [ ] **Step 1: Failing check.** `scripts/check-unit.sh` gains assertions (it already checks the unit's capability line): `AmbientCapabilities` and `CapabilityBoundingSet` are exactly `CAP_AUDIT_READ CAP_BPF CAP_PERFMON`; `SystemCallFilter` contains a line allowing `bpf`; no line allows `perf_event_open`. Run `bash scripts/check-unit.sh` — Expected: FAIL.
- [ ] **Step 2: The unit:**

```ini
AmbientCapabilities=CAP_AUDIT_READ CAP_BPF CAP_PERFMON
CapabilityBoundingSet=CAP_AUDIT_READ CAP_BPF CAP_PERFMON
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
# The eBPF watcher loads its program with bpf() (in @privileged); nothing else
# from that group. CAP_BPF and CAP_PERFMON are dropped once it is attached.
SystemCallFilter=bpf
```

Verify with `systemd-analyze verify` and under the existing "RPM under systemd" job that a later `SystemCallFilter=bpf` re-allows it (systemd applies the lines in order). Run `bash scripts/check-unit.sh` — Expected: PASS.
- [ ] **Step 3: Real kernel, eBPF run.** In `alarms-kernel-e2e.sh`, add a second phase: load Fedora's `-a task,never` (`sudo auditctl -a task,never`), stop auditd (`sudo systemctl stop auditd || true`), remove the agent's audit rule (`sudo auditctl -D`, then re-add only `-a task,never`), run the `alarms_kernel` test binary as nobody with `CAP_BPF,CAP_PERFMON` (`sudo setpriv --reuid=nobody --regid=nogroup --clear-groups --inh-caps=+bpf,+perfmon --ambient-caps=+bpf,+perfmon`), with fake-nginx started BEFORE the agent. Expected: `alarm.web_server.shell` raised for the shell fake-nginx starts, health `source: ebpf`, and `grep -E '^Cap(Eff|Prm)' /proc/<agent pid>/status` decodes (`capsh --decode`) without `cap_bpf`/`cap_perfmon` once attached.
- [ ] **Step 4: Cost.** `scripts/alarms-cost.sh` runs its load once per source (`process_events_source` absent vs `"audit"`) and fails when eBPF's user CPU per 1,000 starts exceeds the audit run's. Record both numbers in the job summary.
- [ ] **Step 5: Docs.** `packaging.md`: the new capabilities, why `bpf` is allowed, the drop after attach. Agent and collectors pages: the two sources, the choice, the reasons, the test switch, and `docs/specs/2026-10-08-ebpf-process-watcher-design.md`. `docs/components/README.md`: the eBPF crate's line.
- [ ] **Step 6: Local gate** (workspace `testing.md` §4, with `--all-features` now needing nightly + bpf-linker): `cargo fmt --all --check`, clippy, docs, `cargo test --locked --workspace --all-features`, `cargo audit --deny warnings`, `bash scripts/check-unit.sh`, and `scripts/build-rpm.sh` in a Fedora container.
- [ ] **Step 7: Commit, PR** `git commit -m "Unit: CAP_BPF, CAP_PERFMON and bpf() for the eBPF watcher; real-kernel and cost checks"`. One agent PR for Tasks 3–9 (or one per task if the reviewer prefers); every CI job green, including "Alarms on a real kernel" and "Alarms cost".

---

## After Plan A

Plan B (packaging: `%post` only on fallback hosts, the 0.2.5 upgrade restore, `audit-fallback`) and Plan C (platform store and console, lab checks on every system) are written once Plan A is merged; their interfaces are `AlarmHealth.source`/`fallback` (Task 3) and the unit (Task 9).
