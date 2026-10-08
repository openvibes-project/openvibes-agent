//! Process starts from the eBPF exec program (`ebpf/openvibes-agent-ebpf`),
//! built by this crate's `build.rs` with feature `ebpf`.
//!
//! [`open_ebpf`] reads the field offsets from the running kernel's BTF
//! ([`offsets_from_btf`]), patches them into the program's globals, loads
//! and attaches it; [`EbpfStarts`] is then a [`StartSource`] over its ring
//! buffer. Records are decoded by byte offset (this crate forbids unsafe
//! code); the layout is the eBPF crate's `src/record.rs`, included below.

use std::{error::Error, io, time::Duration};

use aya::{
    Btf, Ebpf, EbpfLoader,
    maps::{Array, MapData, RingBuf},
    programs::{BtfTracePoint, ProgramError},
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

pub use super::btf::{MissingField, Offsets, attach_only, offsets_from_btf, typedef_id};
use super::{Next, ProcessStart, StartSource};

#[allow(dead_code)] // `Header`, `Scratch` and `EVENTS_BYTES` are the program's.
#[path = "../../../../ebpf/openvibes-agent-ebpf/src/record.rs"]
mod record;
use record::{
    ARG_BYTES, ARGS_LEN_AT, ARGS_TRUNCATED_AT, EUID_AT, HEADER_BYTES, PATH_BYTES,
    PATH_FROM_FILENAME_AT, PATH_LEN_AT, PID_AT, PPID_AT, UID_AT,
};

/// The compiled object (ELF, `bpfel`), 8-byte aligned as aya needs.
pub static OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/openvibes-agent-ebpf"));

const VMLINUX: &str = "/sys/kernel/btf/vmlinux";
/// The typedef a BTF tracepoint on `sched_process_exec` attaches by.
const ATTACH_TYPEDEF: &str = "btf_trace_sched_process_exec";
/// How long [`EbpfStarts::next`] waits for a record.
const WAIT: Duration = Duration::from_millis(200);
/// Bytes of a verifier log kept in [`EbpfError::Verifier`] (its end, where
/// the kernel names the refusal).
const VERIFIER_KEPT: usize = 2_048;
const EPERM: i32 = 1;
const EACCES: i32 = 13;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Why the eBPF source could not start; the caller falls back to audit.
#[derive(Debug)]
pub enum EbpfError {
    /// The kernel has no `/sys/kernel/btf/vmlinux`.
    NoBtf,
    /// The kernel's BTF lacks this struct or field.
    MissingField(&'static str),
    /// `EPERM` and the agent lacks `CAP_BPF` or `CAP_PERFMON` (a tracing
    /// program needs both).
    Capability,
    /// Any failure under `lockdown=confidentiality`.
    Lockdown,
    /// Any other `EPERM`/`EACCES` (an LSM such as SELinux said no).
    LsmDenied,
    /// The verifier refused the program: the end of its log.
    Verifier(String),
    /// Anything else, as text.
    Other(String),
}

/// The loaded and attached program; a [`StartSource`] over its ring buffer.
pub struct EbpfStarts {
    events: RingBuf<MapData>,
    dropped: Array<MapData, u64>,
    /// `DROPPED` as last reported.
    seen_dropped: u64,
    /// Holds the program and its link: dropping it detaches.
    _ebpf: Ebpf,
}

/// Loads and attaches the exec program on the running kernel.
pub fn open_ebpf() -> Result<EbpfStarts, EbpfError> {
    let raw = std::fs::read(VMLINUX).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => EbpfError::NoBtf,
        _ => EbpfError::Other(format!("{VMLINUX}: {e}")),
    })?;
    let offsets = offsets_from_btf(&raw).map_err(|MissingField(f)| EbpfError::MissingField(f))?;
    let attach = typedef_id(&raw, ATTACH_TYPEDEF).ok_or(EbpfError::MissingField(ATTACH_TYPEDEF))?;
    drop(raw);
    // Only what the attach needs, not the whole kernel BTF (the program has
    // no CO-RE relocations: its offsets are the globals above).
    let btf = Btf::parse(
        &attach_only(attach, ATTACH_TYPEDEF),
        aya::Endianness::default(),
    )
    .map_err(|e| failure(&e, ""))?;
    let cpus =
        aya::util::nr_cpus().map_err(|(what, e)| EbpfError::Other(format!("{what}: {e}")))?;
    let cpus = u32::try_from(cpus).map_err(|e| EbpfError::Other(e.to_string()))?;

    let mut loader = EbpfLoader::new();
    loader.btf(Some(&btf)).map_max_entries("SCRATCH", cpus);
    let globals = offsets.globals();
    for (name, value) in &globals {
        loader.override_global(name, value, true);
    }
    let mut ebpf = loader.load(OBJECT).map_err(|e| {
        let log = match &e {
            aya::EbpfError::ProgramError(ProgramError::LoadError { verifier_log, .. }) => {
                verifier_log.to_string()
            }
            _ => String::new(),
        };
        failure(&e, &log)
    })?;
    let program: &mut BtfTracePoint = ebpf
        .program_mut("sched_process_exec")
        .ok_or_else(|| EbpfError::Other("no sched_process_exec program".into()))?
        .try_into()
        .map_err(|e| failure(&e, ""))?;
    program
        .load("sched_process_exec", &btf)
        .map_err(|e| failure(&e, &program_log(&e)))?;
    program
        .attach()
        .map_err(|e| failure(&e, &program_log(&e)))?;

    let map = |name: &str, ebpf: &mut Ebpf| {
        ebpf.take_map(name)
            .ok_or_else(|| EbpfError::Other(format!("no {name} map")))
    };
    let events = RingBuf::try_from(map("EVENTS", &mut ebpf)?).map_err(|e| failure(&e, ""))?;
    let dropped = Array::try_from(map("DROPPED", &mut ebpf)?).map_err(|e| failure(&e, ""))?;
    let seen_dropped = dropped.get(&0, 0).unwrap_or(0);
    Ok(EbpfStarts {
        events,
        dropped,
        seen_dropped,
        _ebpf: ebpf,
    })
}

fn program_log(e: &ProgramError) -> String {
    match e {
        ProgramError::LoadError { verifier_log, .. } => verifier_log.to_string(),
        _ => String::new(),
    }
}

/// Maps a load failure, gathering what [`classify`] needs.
fn failure(e: &(dyn Error + 'static), log: &str) -> EbpfError {
    let mut errno = None;
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(io) = err.downcast_ref::<io::Error>() {
            errno = io.raw_os_error();
            break;
        }
        cur = err.source();
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let lockdown = std::fs::read_to_string("/sys/kernel/security/lockdown").unwrap_or_default();
    let mut message = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        message.push_str(": ");
        message.push_str(&s.to_string());
        src = s.source();
    }
    classify(errno, log, cap_eff(&status), &lockdown, message)
}

/// The pure part of the error mapping.
fn classify(
    errno: Option<i32>,
    verifier_log: &str,
    cap_eff: u64,
    lockdown: &str,
    message: String,
) -> EbpfError {
    let caps = (1 << CAP_BPF) | (1 << CAP_PERFMON);
    match errno {
        Some(EPERM) if cap_eff & caps != caps => EbpfError::Capability,
        // Whatever the errno: this lockdown refuses `bpf_probe_read_kernel`
        // in the verifier (EINVAL and a log), not with EPERM.
        _ if lockdown.contains("[confidentiality]") => EbpfError::Lockdown,
        Some(EPERM) => EbpfError::LsmDenied,
        _ if !verifier_log.trim().is_empty() => EbpfError::Verifier(log_end(verifier_log)),
        Some(EACCES) => EbpfError::LsmDenied,
        _ => EbpfError::Other(message),
    }
}

/// The last [`VERIFIER_KEPT`] bytes, from a line start.
fn log_end(log: &str) -> String {
    let log = log.trim_end();
    let mut from = log.len().saturating_sub(VERIFIER_KEPT);
    while !log.is_char_boundary(from) {
        from += 1;
    }
    let tail = &log[from..];
    match (from, tail.find('\n')) {
        (0, _) | (_, None) => tail.to_owned(),
        (_, Some(nl)) => tail[nl + 1..].to_owned(),
    }
}

/// Effective capabilities from `/proc/self/status` text (0 if absent).
fn cap_eff(status: &str) -> u64 {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        .unwrap_or(0)
}

impl StartSource for EbpfStarts {
    fn next(&mut self) -> Next {
        let mut waited = false;
        loop {
            while let Some(item) = self.events.next() {
                if let Some(start) = decode(&item, now_unix_ms()) {
                    return Next::Start(start);
                }
                // A malformed record (never seen): skip it.
            }
            if let Ok(now) = self.dropped.get(&0, 0) {
                let lost = lost_since(self.seen_dropped, now);
                self.seen_dropped = now;
                if matches!(lost, Next::Lost(_)) {
                    return lost;
                }
            }
            if waited {
                return Next::Idle;
            }
            let mut fds = [PollFd::new(&self.events, PollFlags::IN)];
            let timeout = Timespec::try_from(WAIT).unwrap_or_default();
            match poll(&mut fds, Some(&timeout)) {
                Ok(_) | Err(rustix::io::Errno::INTR) => waited = true,
                Err(_) => return Next::Closed,
            }
        }
    }
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// `Lost(delta)` when the `DROPPED` counter grew, else `Idle`.
fn lost_since(previous: u64, current: u64) -> Next {
    match current.checked_sub(previous) {
        Some(n) if n > 0 => Next::Lost(n),
        _ => Next::Idle,
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|w| w.try_into().ok())
        .map_or(0, u32::from_ne_bytes)
}

/// Decodes one ring-buffer record. `None`: shorter than the header.
/// Lengths are clamped to the record and to the program's maximums;
/// `parent` is the forwarder's to fill.
pub fn decode(bytes: &[u8], now_unix_ms: i64) -> Option<ProcessStart> {
    let body = bytes.get(HEADER_BYTES..)?;
    let path_len = (u32_at(bytes, PATH_LEN_AT) as usize)
        .min(PATH_BYTES)
        .min(body.len());
    let (path, rest) = body.split_at(path_len);
    let want = u32_at(bytes, ARGS_LEN_AT) as usize;
    let args_len = want.min(ARG_BYTES).min(rest.len());
    let args = &rest[..args_len];
    let args = args.strip_suffix(&[0]).unwrap_or(args);
    let args: Vec<Vec<u8>> = if args.is_empty() {
        Vec::new()
    } else {
        args.split(|&c| c == 0).map(<[u8]>::to_vec).collect()
    };
    let exe = path.split(|&c| c == 0).next().unwrap_or_default();
    // No path at all (neither walk nor filename read): argv[0] says more
    // than nothing.
    let exe = match (exe, args.first()) {
        (b"", Some(first)) => first.clone(),
        _ => exe.to_vec(),
    };
    Some(ProcessStart {
        pid: u32_at(bytes, PID_AT),
        ppid: u32_at(bytes, PPID_AT),
        uid: u32_at(bytes, UID_AT),
        euid: u32_at(bytes, EUID_AT),
        exe,
        exe_from_filename: bytes[PATH_FROM_FILENAME_AT] != 0,
        args,
        args_truncated: bytes[ARGS_TRUNCATED_AT] != 0 || args_len < want,
        cwd: None,
        at_unix_ms: now_unix_ms,
        parent: None,
    })
}

#[cfg(test)]
#[path = "ebpf_tests.rs"]
mod tests;
