//! One process start as the eBPF program writes it to the `EVENTS` ring
//! buffer. Shared with user space (`#[path]` include from
//! `openvibes-collectors`), so it holds only plain data and constants.
//!
//! A record is variable-size: a [`Header`] of [`HEADER_BYTES`] bytes, then
//! `path_len` bytes of path, then `args_len` bytes of arguments, with
//! nothing after them. All integers are in the host's byte order.
//!
//! - Path: `bprm->filename` as the kernel string read returns it, at most
//!   [`PATH_BYTES`], including its NUL when it fits.
//! - Args: the new process's `mm->arg_start..arg_end`, NUL-separated as in
//!   `/proc/<pid>/cmdline`, at most [`ARG_BYTES`]. `args_truncated` is 1
//!   when more were there, or when reading them failed (then `args_len` is 0).
//!
//! User space decodes by the `*_AT` byte offsets below (the collectors
//! crate forbids unsafe code, so it never casts bytes to [`Header`]); it must
//! check `HEADER_BYTES + path_len + args_len <= record length`.
//!
//! Maps the loader must know:
//! - `EVENTS`: ring buffer, [`EVENTS_BYTES`].
//! - `DROPPED`: `Array<u64>`, one slot; records lost to a full ring buffer.
//! - `SCRATCH`: `Array<Scratch>` declared with ONE entry as a placeholder.
//!   The loader must set it to the number of possible CPUs
//!   (`EbpfLoader::map_max_entries("SCRATCH", nr_cpus)`); the program uses
//!   slot `bpf_get_smp_processor_id()` and drops the record if the slot is
//!   missing. Not a per-CPU array: per-CPU values are capped at 32 KiB
//!   (E2BIG on every kernel tried).

/// Argument bytes kept per record; equals the agent's `EVENT_ARG_BYTES`.
pub const ARG_BYTES: usize = 65_536;
/// Path bytes kept per record (`PATH_MAX`).
pub const PATH_BYTES: usize = 4_096;
/// Size of the `EVENTS` ring buffer.
pub const EVENTS_BYTES: u32 = 256 * 1024;

/// The fixed start of every record.
#[repr(C)]
pub struct Header {
    /// Thread-group id (the process id user space sees).
    pub pid: u32,
    /// Thread-group id of `real_parent`.
    pub ppid: u32,
    /// Real user id.
    pub uid: u32,
    /// Effective user id.
    pub euid: u32,
    /// `bpf_ktime_get_ns()` at exec (monotonic, boot-relative).
    pub ktime_ns: u64,
    /// Path bytes after the header.
    pub path_len: u32,
    /// Argument bytes after the path.
    pub args_len: u32,
    /// 1 if arguments were cut or could not be read, else 0.
    pub args_truncated: u8,
    /// Zero; pads the header to 8 bytes.
    pub _pad: [u8; 7],
}

/// Byte offset of `pid` (u32).
pub const PID_AT: usize = 0;
/// Byte offset of `ppid` (u32).
pub const PPID_AT: usize = 4;
/// Byte offset of `uid` (u32).
pub const UID_AT: usize = 8;
/// Byte offset of `euid` (u32).
pub const EUID_AT: usize = 12;
/// Byte offset of `ktime_ns` (u64).
pub const KTIME_NS_AT: usize = 16;
/// Byte offset of `path_len` (u32).
pub const PATH_LEN_AT: usize = 24;
/// Byte offset of `args_len` (u32).
pub const ARGS_LEN_AT: usize = 28;
/// Byte offset of `args_truncated` (u8).
pub const ARGS_TRUNCATED_AT: usize = 32;
/// Header size; the path starts here.
pub const HEADER_BYTES: usize = 40;

/// The scratch slot a record is assembled in before it is output.
#[repr(C)]
pub struct Scratch {
    /// The header, written first.
    pub header: Header,
    /// Path, then args right after it.
    pub buf: [u8; PATH_BYTES + ARG_BYTES],
}

// The layout user space relies on; a change here fails the build.
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(offset_of!(Header, pid) == PID_AT);
    assert!(offset_of!(Header, ppid) == PPID_AT);
    assert!(offset_of!(Header, uid) == UID_AT);
    assert!(offset_of!(Header, euid) == EUID_AT);
    assert!(offset_of!(Header, ktime_ns) == KTIME_NS_AT);
    assert!(offset_of!(Header, path_len) == PATH_LEN_AT);
    assert!(offset_of!(Header, args_len) == ARGS_LEN_AT);
    assert!(offset_of!(Header, args_truncated) == ARGS_TRUNCATED_AT);
    assert!(size_of::<Header>() == HEADER_BYTES);
    assert!(offset_of!(Scratch, buf) == HEADER_BYTES);
    // The program bounds lengths with `& (MAX - 1)`.
    assert!(ARG_BYTES.is_power_of_two() && PATH_BYTES.is_power_of_two());
};
