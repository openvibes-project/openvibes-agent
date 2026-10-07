//! Process starts from the kernel: a `tp_btf/sched_process_exec` program
//! that writes one variable-size record per exec to the `EVENTS` ring buffer
//! (layout in `record.rs`).
//!
//! Why unsafe, and why this licence: the program reads kernel and process
//! memory through BPF helpers (raw pointers into `task_struct`, `mm_struct`,
//! `cred`, `linux_binprm` and user memory), which is unsafe by nature in Rust;
//! the kernel verifier checks every access before the program may run. So
//! this crate stands outside the agent workspace and its
//! `forbid(unsafe_code)`, by decision (2026-10-08). It is licensed
//! `MIT OR GPL-2.0` and declares `Dual MIT/GPL` to the kernel, because the
//! kernel lets only GPL-compatible programs call `bpf_probe_read_*`.
//!
//! Struct field offsets are not compiled in: the loader reads them from the
//! running kernel's BTF and sets the `u32` globals below
//! (`EbpfLoader::override_global`) before loading.
//!
//! Every variable length is bounded by a constant branch for the maximum and
//! `& (MAX - 1)` right before use: the 6.8 verifier refused a plain clamp
//! after LLVM spilled the value (spike, 2026-10-08). Keep that shape.

#![no_std]
#![no_main]

mod record;

use aya_ebpf::{
    helpers::{
        bpf_probe_read_kernel,
        generated::{
            bpf_get_current_task, bpf_get_smp_processor_id, bpf_ktime_get_ns,
            bpf_probe_read_kernel_str, bpf_probe_read_user,
        },
    },
    macros::{btf_tracepoint, map},
    maps::{Array, RingBuf},
    programs::BtfTracePointContext,
};
use record::{ARG_BYTES, EVENTS_BYTES, HEADER_BYTES, PATH_BYTES, Scratch};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(EVENTS_BYTES, 0);

/// Records dropped because `EVENTS` was full or no scratch slot was found.
#[map]
static DROPPED: Array<u64> = Array::with_max_entries(1, 0);

/// One slot per CPU; 1 is a placeholder the loader overrides with the CPU
/// count (`map_max_entries("SCRATCH", nr_cpus)`).
#[map]
static SCRATCH: Array<Scratch> = Array::with_max_entries(1, 0);

// Byte offsets, set by the loader from /sys/kernel/btf/vmlinux.
#[unsafe(no_mangle)]
static TASK_REAL_PARENT: u32 = 0;
#[unsafe(no_mangle)]
static TASK_TGID: u32 = 0;
#[unsafe(no_mangle)]
static TASK_MM: u32 = 0;
#[unsafe(no_mangle)]
static TASK_CRED: u32 = 0;
#[unsafe(no_mangle)]
static MM_ARG_START: u32 = 0;
#[unsafe(no_mangle)]
static MM_ARG_END: u32 = 0;
#[unsafe(no_mangle)]
static CRED_UID: u32 = 0;
#[unsafe(no_mangle)]
static CRED_EUID: u32 = 0;
#[unsafe(no_mangle)]
static BINPRM_FILENAME: u32 = 0;

/// Read a global the loader patched (volatile, so it is not folded to 0).
#[inline(always)]
fn off(v: &u32) -> usize {
    unsafe { core::ptr::read_volatile(v) as usize }
}

#[inline(always)]
unsafe fn field<T>(base: *const u8, offset: usize) -> Result<T, i32> {
    unsafe { bpf_probe_read_kernel(base.add(offset) as *const T) }
}

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> i32 {
    if let Err(Lost::Record) = unsafe { record_exec(&ctx) } {
        if let Some(n) = DROPPED.get_ptr_mut(0) {
            // Not atomic (core has no atomic add for the BPF target): drops
            // on two CPUs at the same instant may count once. A diagnostic.
            unsafe { *n += 1 };
        }
    }
    0
}

/// Why no record went out.
enum Lost {
    /// A kernel read failed (the process is gone or an offset is wrong).
    Read,
    /// No scratch slot, or the ring buffer was full: counted in `DROPPED`.
    Record,
}

unsafe fn record_exec(ctx: &BtfTracePointContext) -> Result<(), Lost> {
    let slot = SCRATCH
        .get_ptr_mut(unsafe { bpf_get_smp_processor_id() })
        .ok_or(Lost::Record)?;
    // Header first, straight into the slot: fewer live values to spill.
    let h = unsafe { &mut (*slot).header };
    let task = unsafe { bpf_get_current_task() } as *const u8;
    unsafe {
        h.pid = field(task, off(&TASK_TGID)).map_err(|_| Lost::Read)?;
        let parent: *const u8 = field(task, off(&TASK_REAL_PARENT)).map_err(|_| Lost::Read)?;
        h.ppid = field(parent, off(&TASK_TGID)).map_err(|_| Lost::Read)?;
        let cred: *const u8 = field(task, off(&TASK_CRED)).map_err(|_| Lost::Read)?;
        h.uid = field(cred, off(&CRED_UID)).map_err(|_| Lost::Read)?;
        h.euid = field(cred, off(&CRED_EUID)).map_err(|_| Lost::Read)?;
        h.ktime_ns = bpf_ktime_get_ns();
    }
    let mm: *const u8 = unsafe { field(task, off(&TASK_MM)) }.map_err(|_| Lost::Read)?;
    let arg_start: u64 = unsafe { field(mm, off(&MM_ARG_START)) }.map_err(|_| Lost::Read)?;
    let arg_end: u64 = unsafe { field(mm, off(&MM_ARG_END)) }.map_err(|_| Lost::Read)?;
    // sched_process_exec(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
    let bprm: *const u8 = ctx.arg(2);
    let filename: *const u8 =
        unsafe { field(bprm, off(&BINPRM_FILENAME)) }.map_err(|_| Lost::Read)?;

    let buf = unsafe { (*slot).buf.as_mut_ptr() };
    // Path: kernel string, length including its NUL.
    let r = unsafe {
        bpf_probe_read_kernel_str(buf as *mut _, PATH_BYTES as u32, filename as *const _)
    };
    let plen: usize = if r <= 0 {
        0
    } else if r as usize >= PATH_BYTES {
        PATH_BYTES
    } else {
        (r as usize) & (PATH_BYTES - 1)
    };
    h.path_len = plen as u32;

    // Args: user memory, right after the path.
    let n = arg_end.wrapping_sub(arg_start);
    let mut cut = n > ARG_BYTES as u64;
    let want: usize = if n >= ARG_BYTES as u64 {
        ARG_BYTES
    } else {
        (n as usize) & (ARG_BYTES - 1)
    };
    let read =
        unsafe { bpf_probe_read_user(buf.add(plen) as *mut _, want as u32, arg_start as *const _) };
    let alen = if read < 0 {
        cut |= want > 0;
        0
    } else {
        want
    };
    h.args_len = alen as u32;
    h.args_truncated = u8::from(cut);
    h._pad = [0; 7];

    let rec = unsafe { core::slice::from_raw_parts(slot as *const u8, HEADER_BYTES + plen + alen) };
    EVENTS.output::<[u8]>(rec, 0).map_err(|_| Lost::Record)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
