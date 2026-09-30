//! Process starts from the kernel audit system (protocol P14).
//!
//! The agent reads the audit multicast group with only `CAP_AUDIT_READ`; it
//! never changes audit rules or reads `/var/log/audit`. The RPM ships the
//! rule (`-a always,exit -S execve,execveat -k openvibes-exec`); without it
//! no records arrive and no alarms are raised.
//!
//! Test records are synthetic, built from the kernel's record format (see
//! [`records`]); the real-kernel CI job (`alarms-kernel`) checks the format
//! against a live kernel.

mod records;

pub use records::{
    EVENT_ARG_BYTES, EVENT_WAIT, EXEC_KEY, Joiner, MAX_MESSAGE, OPEN_EVENTS, ProcessStart,
};

#[cfg(test)]
mod tests;
