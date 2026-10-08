//! Which source feeds process starts: the eBPF program first, kernel audit
//! when it cannot load (or when the configuration forces audit, for tests).

use openvibes_core::{AlarmFallback, AlarmSource, CollectorError, FallbackDetail};

#[cfg(feature = "ebpf")]
use super::ebpf::{EbpfError, open_ebpf};
use super::{AuditStarts, StartSource, open_audit_socket};

/// The chosen source, and what health reports about it.
pub struct Opened {
    /// What feeds alarms.
    pub source: AlarmSource,
    /// Why eBPF is not in use; `None` on eBPF or when audit was forced.
    pub fallback: Option<AlarmFallback>,
    /// The starts; `None` when nothing opened (alarms off).
    pub starts: Option<Box<dyn StartSource>>,
    /// Why the audit socket did not open, when nothing did.
    pub error: Option<CollectorError>,
}

/// eBPF first unless `force_audit`; on failure the audit socket. `starts`
/// `None`: alarms off. `audit_rule_loaded` fills the fallback's field when
/// audit opens. Logs one line naming the source (and why not eBPF).
pub fn open_process_starts(force_audit: bool, audit_rule_loaded: fn() -> bool) -> Opened {
    let why = if force_audit {
        None
    } else {
        match try_ebpf() {
            Ok(starts) => {
                eprintln!("openvibes-agent: reading process starts with eBPF");
                return Opened {
                    source: AlarmSource::Ebpf,
                    fallback: None,
                    starts: Some(starts),
                    error: None,
                };
            }
            Err(why) => Some(why),
        }
    };
    let prefix = why.as_ref().map_or_else(String::new, |(detail, message)| {
        format!("eBPF unavailable ({}: {message}); ", label(*detail))
    });
    let fallback = |loaded| {
        why.as_ref().map(|(detail, _)| AlarmFallback {
            detail: *detail,
            audit_rule_loaded: loaded,
        })
    };
    match open_audit_socket() {
        Ok(socket) => {
            let buffer = socket.recv_buffer().map_or_else(String::new, |b| {
                format!(" (receive buffer {} KiB)", b / 1024)
            });
            eprintln!("openvibes-agent: {prefix}reading process starts from kernel audit{buffer}");
            Opened {
                source: AlarmSource::Audit,
                fallback: fallback(audit_rule_loaded()),
                starts: Some(Box::new(AuditStarts::new(socket))),
                error: None,
            }
        }
        Err(error) => {
            eprintln!(
                "openvibes-agent: {prefix}kernel audit unavailable ({}); alarms are off",
                error.message
            );
            Opened {
                source: AlarmSource::None,
                fallback: fallback(false),
                starts: None,
                error: Some(error),
            }
        }
    }
}

#[cfg(feature = "ebpf")]
fn try_ebpf() -> Result<Box<dyn StartSource>, (FallbackDetail, String)> {
    match open_ebpf() {
        Ok(starts) => Ok(Box::new(starts)),
        Err(error) => Err((fallback_detail(&error), message(&error))),
    }
}

#[cfg(not(feature = "ebpf"))]
fn try_ebpf() -> Result<Box<dyn StartSource>, (FallbackDetail, String)> {
    Err((FallbackDetail::Other, "this build has no eBPF".into()))
}

/// The health detail for an eBPF failure.
#[cfg(feature = "ebpf")]
#[must_use]
pub fn fallback_detail(error: &EbpfError) -> FallbackDetail {
    match error {
        EbpfError::NoBtf => FallbackDetail::NoBtf,
        EbpfError::Capability => FallbackDetail::Capability,
        EbpfError::Lockdown => FallbackDetail::Lockdown,
        EbpfError::LsmDenied => FallbackDetail::LsmDenied,
        EbpfError::Verifier(_) => FallbackDetail::Verifier,
        EbpfError::MissingField(_) | EbpfError::Other(_) => FallbackDetail::Other,
    }
}

/// One line for the log.
#[cfg(feature = "ebpf")]
fn message(error: &EbpfError) -> String {
    match error {
        EbpfError::NoBtf => "no /sys/kernel/btf/vmlinux".into(),
        EbpfError::MissingField(field) => format!("the kernel's BTF lacks {field}"),
        EbpfError::Capability => "CAP_BPF or CAP_PERFMON missing".into(),
        EbpfError::Lockdown => "kernel lockdown=confidentiality".into(),
        EbpfError::LsmDenied => "a security module denied it".into(),
        // The log's last line names the refusal.
        EbpfError::Verifier(log) => format!(
            "the verifier refused the program: {}",
            log.lines().last().unwrap_or_default()
        ),
        EbpfError::Other(text) => text.clone(),
    }
}

/// The detail as health spells it.
fn label(detail: FallbackDetail) -> &'static str {
    match detail {
        FallbackDetail::NoBtf => "no_btf",
        FallbackDetail::Capability => "capability",
        FallbackDetail::Lockdown => "lockdown",
        FallbackDetail::LsmDenied => "lsm_denied",
        FallbackDetail::Verifier => "verifier",
        FallbackDetail::Other => "other",
    }
}
