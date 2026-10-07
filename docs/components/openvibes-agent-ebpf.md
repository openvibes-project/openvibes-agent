# openvibes-agent-ebpf

## Purpose

The in-kernel half of the eBPF process watcher
(`docs/specs/2026-10-08-ebpf-process-watcher-design.md`): a Rust
(`aya-ebpf` 0.2.1) program on the `tp_btf/sched_process_exec` tracepoint
that writes one record per successful exec to a ring buffer. User space
(`openvibes-collectors`, feature `ebpf`) embeds the compiled object, sets
the struct offsets for the running kernel, loads it and reads the records.
Kernel audit stays the fallback.

The crate lives in `ebpf/openvibes-agent-ebpf`, outside the workspace
(root `exclude = ["ebpf"]`), and builds only for `bpfel-unknown-none`.

## Interfaces

- **Program:** `sched_process_exec` in section
  `tp_btf/sched_process_exec`. It reads the current task's tgid,
  `real_parent->tgid`, `cred->uid`/`euid`, `mm->arg_start..arg_end`
  (user memory) and `bprm->filename` (tracepoint argument 2).
- **Record** (`src/record.rs`, included by user space with `#[path]`):
  a 40-byte header, then the path bytes, then the argument bytes; the
  ring-buffer item is exactly that long. Host byte order.

  | Offset | Field | Type |
  |---|---|---|
  | 0 | `pid` (tgid) | u32 |
  | 4 | `ppid` (real parent's tgid) | u32 |
  | 8 | `uid` | u32 |
  | 12 | `euid` | u32 |
  | 16 | `ktime_ns` (`bpf_ktime_get_ns`) | u64 |
  | 24 | `path_len` | u32 |
  | 28 | `args_len` | u32 |
  | 32 | `args_truncated` (0/1) | u8 |
  | 33 | padding (zero) | 7 bytes |
  | 40 | path, then args | bytes |

  Path: at most `PATH_BYTES` (4,096), including its NUL when it fits.
  Args: at most `ARG_BYTES` (65,536, equal to the agent's
  `EVENT_ARG_BYTES`), NUL-separated as in `/proc/<pid>/cmdline`;
  `args_truncated` is 1 when there were more or the read failed. Decoders
  use the `*_AT` constants and must check
  `HEADER_BYTES + path_len + args_len <= item length`. Compile-time
  asserts in `record.rs` tie the constants to the struct.
- **Globals** the loader sets with `EbpfLoader::override_global` (u32 byte
  offsets from `/sys/kernel/btf/vmlinux`): `TASK_REAL_PARENT`,
  `TASK_TGID`, `TASK_MM`, `TASK_CRED`, `MM_ARG_START`, `MM_ARG_END`,
  `CRED_UID`, `CRED_EUID`, `BINPRM_FILENAME`.
- **Maps:**
  - `EVENTS`: ring buffer, 256 KiB (about three maximum-size records).
  - `DROPPED`: `Array<u64>`, one slot: records lost to a full ring buffer
    or a missing scratch slot.
  - `SCRATCH`: `Array<Scratch>` (69,672-byte value) declared with one
    entry. The loader must set it to the CPU count
    (`map_max_entries("SCRATCH", nr_cpus)`); the program uses slot
    `bpf_get_smp_processor_id()`. Not a per-CPU array: per-CPU values are
    capped at 32 KiB (E2BIG on every kernel tried).
- **Embedded object:** `openvibes_collectors::process_events::ebpf::OBJECT`
  (feature `ebpf`, Linux targets only).

## Build

`crates/openvibes-collectors/build.rs` builds it with `aya-build` 0.2 when
feature `ebpf` is on and the target is Linux, and the object lands in
`OUT_DIR` as `openvibes-agent-ebpf`. It needs:

- the nightly pinned in `ebpf/openvibes-agent-ebpf/rust-toolchain.toml`
  (`nightly-2026-10-07`, rustc 8d1a76430) with `rust-src`:
  `(cd ebpf/openvibes-agent-ebpf && rustup toolchain install)`;
- `bpf-linker` 0.11.1 on `PATH`. CI downloads the release's static
  `bpf-linker-x86_64-unknown-linux-musl.tar.zst` and checks its SHA-256
  (`cargo install bpf-linker` needs LLVM's development files).

Builds without the feature, and non-Linux targets, need neither. The
lockfile `ebpf/openvibes-agent-ebpf/Cargo.lock` is committed.

## Configuration

None; offsets and the scratch size come from the loader.

## Failure behaviour

- A kernel read that fails (process gone, wrong offset): no record, not
  counted.
- No scratch slot or a full ring buffer: no record, `DROPPED` + 1. The
  increment is not atomic (`core` has no atomic add for BPF), so drops on
  two CPUs at the same instant may count once.
- An argument read that fails: the record goes out with `args_len` 0 and
  `args_truncated` 1.
- Every variable length is bounded by a constant branch for the maximum
  plus `& (MAX - 1)` right before use; Ubuntu 6.8's verifier refused a
  plain clamp after LLVM spilled the value. Test every change to the
  program on Ubuntu 6.8.

## Licence and unsafe code

The crate is `MIT OR GPL-2.0` and its `license` section says `Dual MIT/GPL`:
the kernel lets only GPL-compatible programs call `bpf_probe_read_*`. It
uses `unsafe` to read kernel and process memory through BPF helpers, which
the kernel verifier checks before the program runs; that is why it sits
outside the workspace's `forbid(unsafe_code)` (decision 2026-10-08).

## Test

```sh
cargo build -p openvibes-collectors --features ebpf
readelf -SW target/debug/build/openvibes-collectors-*/out/openvibes-agent-ebpf
cargo test --locked -p openvibes-collectors --features ebpf
```

The section list shows `tp_btf/sched_process_exec`, `maps`, `license`,
`.rodata` (the offset globals) and `.BTF`. The unit test checks that
`OBJECT` is a BPF ELF with the program's section. Loading on real kernels
is the eBPF watcher's test (lab fleet, Ubuntu 6.8 included).
