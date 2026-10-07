//! Process starts from the kernel audit system (protocol P14).
//!
//! The agent reads the audit multicast group with only `CAP_AUDIT_READ`; it
//! never changes audit rules or reads `/var/log/audit`. The RPM ships the
//! rule (`-a always,exit -S execve,execveat -k openvibes-exec`); without it
//! no records arrive and no alarms are raised.
//!
//! Test records are synthetic, built from the kernel's record format (see
//! `records.rs`); the real-kernel CI job (`alarms-kernel`) checks the format
//! against a live kernel.

#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub mod ebpf;
mod forward;
mod reader;
mod records;
#[cfg(target_os = "linux")]
mod seed;
#[cfg(target_os = "linux")]
mod socket;

pub use forward::{Next, StartSource, spawn_forwarder};
pub use reader::{AuditStarts, Drops, RECENT_EXECS, Received, Source, spawn_reader};
pub use records::{
    EVENT_ARG_BYTES, EVENT_WAIT, EXEC_KEY, Joiner, MAX_MESSAGE, OPEN_EVENTS, ProcessStart,
    SEEDED_ARG_BYTES, Seeded,
};
#[cfg(target_os = "linux")]
pub use seed::read_process;
#[cfg(target_os = "linux")]
pub use socket::{AuditSocket, open_audit_socket};

use openvibes_core::{CollectorError, CollectorErrorCode, Identifier};

/// Collector id in errors and health.
pub const SOURCE: &str = "process_events";

fn error(code: CollectorErrorCode, message: &str) -> CollectorError {
    CollectorError {
        collector: Identifier::new(SOURCE).expect("static collector id"),
        code,
        message: message.to_owned(),
        retryable: false,
    }
}

/// Not Linux: there is no kernel audit to read.
#[cfg(not(target_os = "linux"))]
pub fn open_audit_socket() -> Result<std::convert::Infallible, CollectorError> {
    Err(error(
        CollectorErrorCode::Unsupported,
        "process events need Linux kernel audit",
    ))
}

#[cfg(test)]
mod tests;
