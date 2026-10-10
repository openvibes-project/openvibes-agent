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
//! `MIT OR GPL-2.0-only` and declares `Dual MIT/GPL` to the kernel, because the
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
            bpf_probe_read_kernel as read_kernel, bpf_probe_read_kernel_str, bpf_probe_read_user,
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
// The exe path walk (`exe_path`).
#[unsafe(no_mangle)]
static BINPRM_FILE: u32 = 0;
#[unsafe(no_mangle)]
static FILE_DENTRY: u32 = 0;
#[unsafe(no_mangle)]
static FILE_MNT: u32 = 0;
#[unsafe(no_mangle)]
static DENTRY_PARENT: u32 = 0;
#[unsafe(no_mangle)]
static DENTRY_NAME: u32 = 0;
#[unsafe(no_mangle)]
static DENTRY_NAME_LEN: u32 = 0;
#[unsafe(no_mangle)]
static VFSMOUNT_ROOT: u32 = 0;
#[unsafe(no_mangle)]
static MOUNT_MNT: u32 = 0;
#[unsafe(no_mangle)]
static MOUNT_PARENT: u32 = 0;
#[unsafe(no_mangle)]
static MOUNT_MOUNTPOINT: u32 = 0;

/// Path components (and mount crossings) the walk follows at most.
const WALK_STEPS: usize = 32;
/// A path component is at most `NAME_MAX` (255) bytes; this bounds it.
const NAME_BYTES: usize = 256;

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
    let buf = unsafe { (*slot).buf.as_mut_ptr() };

    // Path: the exec'd file's absolute path, as audit's `exe=`; if the walk
    // fails, the execve filename as the caller gave it, flagged.
    let walked = match unsafe { field::<*const u8>(bprm, off(&BINPRM_FILE)) } {
        Ok(file) => exe_path(buf, file),
        Err(_) => -1,
    };
    let plen: usize = if walked > 0 {
        h.path_from_filename = 0;
        if walked as usize >= PATH_BYTES {
            PATH_BYTES
        } else {
            (walked as usize) & (PATH_BYTES - 1)
        }
    } else {
        h.path_from_filename = 1;
        let filename: *const u8 =
            unsafe { field(bprm, off(&BINPRM_FILENAME)) }.map_err(|_| Lost::Read)?;
        // Kernel string, length including its NUL.
        let r = unsafe {
            bpf_probe_read_kernel_str(buf as *mut _, PATH_BYTES as u32, filename as *const _)
        };
        if r <= 0 {
            0
        } else if r as usize >= PATH_BYTES {
            PATH_BYTES
        } else {
            (r as usize) & (PATH_BYTES - 1)
        }
    };
    h.path_len = plen as u32;

    // Args: user memory, right after the path.
    // Saturating: arg_end < arg_start must read nothing, not 64 KiB of the
    // environment (which can hold secrets).
    let n = arg_end.saturating_sub(arg_start);
    let read = read_args(unsafe { buf.add(plen) }, n, arg_start);
    let alen: usize = if read <= 0 {
        0
    } else if read as usize >= ARG_BYTES {
        ARG_BYTES
    } else {
        (read as usize) & (ARG_BYTES - 1)
    };
    // Cut, or a failed read of a non-empty range.
    let cut = n > ARG_BYTES as u64 || (read < 0 && n > 0);
    h.args_len = alen as u32;
    h.args_truncated = u8::from(cut);
    h._pad = [0; 6];

    let rec = unsafe { core::slice::from_raw_parts(slot as *const u8, HEADER_BYTES + plen + alen) };
    EVENTS.output::<[u8]>(rec, 0).map_err(|_| Lost::Record)
}

/// Reads `min(n, ARG_BYTES)` bytes of user memory at `src` into `dst`;
/// returns the count, or -1 if the read failed.
///
/// A separate BPF function on purpose: with only these three values live,
/// `n` is bounded in a register right before the helper call. Inlined, LLVM
/// spilled `n` to the stack before the bound and dropped the (provably
/// redundant) mask, and the 6.8 verifier refused the reload (Ubuntu 24.04,
/// "R2 min value is negative", 2026-10-08).
#[inline(never)]
fn read_args(dst: *mut u8, n: u64, src: u64) -> i64 {
    let want: usize = if n >= ARG_BYTES as u64 {
        ARG_BYTES
    } else {
        (n as usize) & (ARG_BYTES - 1)
    };
    let r = unsafe { bpf_probe_read_user(dst as *mut _, want as u32, src as *const _) };
    if r < 0 { -1 } else { want as i64 }
}

/// Writes the absolute path of the open `file` (a `struct file *`) to
/// `buf[..len]` and returns `len`, or -1 when the walk fails: more than
/// [`WALK_STEPS`] steps, a name over `NAME_MAX`, a path over
/// [`PATH_BYTES`] - 1, a read error, or a root that is not a mount's (a
/// file with no path, such as a memfd). What `d_path` gives audit, up to
/// the mount namespace's root, without " (deleted)" for an unlinked file.
///
/// Walks from the file's dentry up `d_parent`; at a mount's root it steps to
/// the mount point in the parent mount (`struct mount`, which embeds the
/// `vfsmount` that `path.mnt` points to); it stops at the root mount (its
/// own parent). Builds the path backwards in `buf[PATH_BYTES..]` (the args
/// area, written later), then copies it to the front. A separate BPF
/// function so the verifier sees few live values (see [`read_args`]).
#[inline(never)]
fn exe_path(buf: *mut u8, file: *const u8) -> i64 {
    match unsafe { walk(buf, file) } {
        Some(len) => len as i64,
        None => -1,
    }
}

#[inline(always)]
unsafe fn walk(buf: *mut u8, file: *const u8) -> Option<usize> {
    let tmp = unsafe { buf.add(PATH_BYTES) };
    let mut dentry: u64 = unsafe { field(file, off(&FILE_DENTRY)) }.ok()?;
    let vfsmnt: u64 = unsafe { field(file, off(&FILE_MNT)) }.ok()?;
    let mut mnt: u64 = vfsmnt.wrapping_sub(off(&MOUNT_MNT) as u64);
    // The path so far is tmp[pos..PATH_BYTES].
    let mut pos: usize = PATH_BYTES;
    let mut done = false;
    for _ in 0..WALK_STEPS {
        let m = mnt as *const u8;
        let root: u64 = unsafe { field(m, off(&MOUNT_MNT) + off(&VFSMOUNT_ROOT)) }.ok()?;
        let d = dentry as *const u8;
        let parent: u64 = unsafe { field(d, off(&DENTRY_PARENT)) }.ok()?;
        if dentry == root || dentry == parent {
            if dentry != root {
                return None;
            }
            let up: u64 = unsafe { field(m, off(&MOUNT_PARENT)) }.ok()?;
            if up == mnt {
                done = true;
                break;
            }
            dentry = unsafe { field(m, off(&MOUNT_MOUNTPOINT)) }.ok()?;
            mnt = up;
            continue;
        }
        let len: u32 = unsafe { field(d, off(&DENTRY_NAME_LEN)) }.ok()?;
        let name: u64 = unsafe { field(d, off(&DENTRY_NAME)) }.ok()?;
        if len == 0 || len as usize >= NAME_BYTES {
            return None;
        }
        let n = bound::<NAME_BYTES>(len as usize);
        if pos < n + 2 {
            return None;
        }
        pos = bound::<PATH_BYTES>(pos - n - 1);
        unsafe { *tmp.add(pos) = b'/' };
        // Bound again right before the read: after `pos < n + 2`, Debian's
        // 6.12 verifier had lost `n`'s unsigned bound (linked registers).
        let size = bound::<NAME_BYTES>(n) as u32;
        let r = unsafe { read_kernel(tmp.add(pos + 1) as *mut _, size, name as *const _) };
        if r < 0 {
            return None;
        }
        dentry = parent;
    }
    if !done || pos >= PATH_BYTES {
        return None;
    }
    let pos = bound::<PATH_BYTES>(pos);
    let len = bound::<PATH_BYTES>(PATH_BYTES - pos);
    let r = unsafe { read_kernel(buf as *mut _, len as u32, tmp.add(pos) as *const _) };
    if r < 0 { None } else { Some(len) }
}

/// `v & (MAX - 1)`, with the `and` kept in the program: the verifier needs
/// it right before a variable offset or size. Without `black_box`, LLVM
/// drops a mask it can prove redundant from an earlier check, and Debian's
/// 6.12 verifier did not carry that check's bound to the helper's size
/// ("R2 unbounded memory access", 2026-10-08).
#[inline(always)]
fn bound<const MAX: usize>(v: usize) -> usize {
    core::hint::black_box(v) & (MAX - 1)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
