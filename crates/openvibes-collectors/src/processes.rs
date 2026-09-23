//! Running processes: `process.names` and `process.count`.
//!
//! Canonical semantics, identical on every OS:
//!
//! - `process.names` (string list): sorted, de-duplicated short names of the
//!   running processes. A name is the OS's short process name truncated to
//!   [`NAME_BYTES`] bytes (Linux's `comm` length) at a character boundary. On
//!   Windows it is lowercased with a trailing `.exe` removed, so `sshd` means
//!   the same everywhere. Names are chosen by the processes themselves and are
//!   spoofable: rules must not treat them as proof of identity.
//! - `process.count` (integer): the number of processes observed.
//!
//! All or nothing: when the list would be incomplete (names hidden from this
//! identity, more distinct names than the list limit, or the deadline passed)
//! the collector emits no facts and one [`CollectorError`], so rules evaluate
//! as unavailable instead of on a partial list.
//!
//! Privileges: Linux reads `/proc/<pid>/comm`, which any user can read unless
//! `/proc` is mounted with `hidepid`; then only root sees every process and
//! other identities get `permission_denied`. Windows lists every process name
//! without administrator rights. macOS support is compiled but not yet
//! verified on a macOS host.

use std::time::Instant;

use openvibes_core::{
    CollectorError, CollectorErrorCode, Fact, FactValue, Identifier, ResourceLimits,
};

/// Longest canonical process name, in bytes.
pub const NAME_BYTES: usize = 15;

/// Collector identifier reported as the source of every fact and error.
const SOURCE: &str = "processes";

/// Collects the running-process facts, or one error if they would be
/// incomplete. Never modifies or signals any process.
pub fn collect_processes(
    deadline: Instant,
    limits: ResourceLimits,
) -> Result<Vec<Fact>, CollectorError> {
    let raw = platform::names(deadline)?;
    if Instant::now() > deadline {
        return Err(error(
            CollectorErrorCode::TimedOut,
            "process scan exceeded its deadline",
            true,
        ));
    }
    facts(raw, cfg!(windows), limits)
}

/// Builds the facts from one raw name per process. A process whose name is
/// empty still counts.
fn facts(
    raw: Vec<String>,
    windows: bool,
    limits: ResourceLimits,
) -> Result<Vec<Fact>, CollectorError> {
    if raw.is_empty() {
        return Err(error(
            CollectorErrorCode::Internal,
            "no processes were observed",
            true,
        ));
    }
    let count = i64::try_from(raw.len()).unwrap_or(i64::MAX);
    let mut names: Vec<String> = raw
        .iter()
        .filter_map(|name| canonical_name(name, windows))
        .collect();
    names.sort_unstable();
    names.dedup();
    if names.len() > limits.fact_list_items {
        return Err(error(
            CollectorErrorCode::InvalidData,
            "more distinct process names than the list limit",
            true,
        ));
    }
    Ok(vec![
        fact("process.names", FactValue::StringList(names)),
        fact("process.count", FactValue::Integer(count)),
    ])
}

/// The canonical form of one OS-reported name; `None` if nothing is left.
fn canonical_name(raw: &str, windows: bool) -> Option<String> {
    let mut name = raw.trim_end_matches('\n').to_owned();
    if windows {
        name = name.to_lowercase();
        if let Some(stem) = name.strip_suffix(".exe") {
            name = stem.to_owned();
        }
    }
    let mut end = name.len().min(NAME_BYTES);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name.truncate(end);
    Some(name).filter(|name| !name.is_empty())
}

fn fact(key: &str, value: FactValue) -> Fact {
    Fact {
        key: Identifier::new(key).expect("static fact key"),
        source: Identifier::new(SOURCE).expect("static collector id"),
        value,
    }
}

fn error(code: CollectorErrorCode, message: &str, retryable: bool) -> CollectorError {
    CollectorError {
        collector: Identifier::new(SOURCE).expect("static collector id"),
        code,
        message: message.to_owned(),
        retryable,
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{
        fs::{self, File},
        io::{self, Read},
        path::Path,
        time::Instant,
    };

    use openvibes_core::{CollectorError, CollectorErrorCode};

    use super::error;

    /// `comm` is at most 16 bytes including the newline; anything longer is
    /// read only this far and then truncated like any other name.
    const COMM_READ_BYTES: u64 = 64;
    /// Linux `ESRCH`: the process exited while its files were being read.
    const ESRCH: i32 = 3;

    pub(super) fn names(deadline: Instant) -> Result<Vec<String>, CollectorError> {
        let mountinfo = fs::read_to_string("/proc/self/mountinfo").map_err(|_| {
            error(
                CollectorErrorCode::Internal,
                "cannot read /proc mount options",
                true,
            )
        })?;
        if hides_processes(&mountinfo) && !rustix::process::geteuid().is_root() {
            return Err(error(
                CollectorErrorCode::PermissionDenied,
                "/proc is mounted with hidepid; other users' processes are hidden",
                false,
            ));
        }
        scan(Path::new("/proc"), deadline)
    }

    /// Whether the `/proc` mount hides other users' processes.
    // ponytail: ignores a `gid=` exemption, so an exempted non-root identity
    // is refused (unavailable, never wrong). Parse `gid=` if that bites.
    pub(super) fn hides_processes(mountinfo: &str) -> bool {
        mountinfo.lines().any(|line| {
            let Some((mount, fs)) = line.split_once(" - ") else {
                return false;
            };
            let mut fs = fs.split(' ');
            let proc_type = fs.next() == Some("proc");
            let hidepid = fs.nth(1).unwrap_or("").split(',').any(|option| {
                option
                    .strip_prefix("hidepid=")
                    .is_some_and(|value| !matches!(value, "0" | "off"))
            });
            mount.split(' ').nth(4) == Some("/proc") && proc_type && hidepid
        })
    }

    /// Reads `comm` of every numeric entry under `proc_root`. A process that
    /// exits mid-scan is skipped; any denied read fails the whole scan.
    pub(super) fn scan(proc_root: &Path, deadline: Instant) -> Result<Vec<String>, CollectorError> {
        let entries = fs::read_dir(proc_root).map_err(|error| io_error(&error))?;
        let mut names = Vec::new();
        for entry in entries {
            if Instant::now() > deadline {
                return Err(error(
                    CollectorErrorCode::TimedOut,
                    "process scan exceeded its deadline",
                    true,
                ));
            }
            let entry = entry.map_err(|error| io_error(&error))?;
            let file_name = entry.file_name();
            let is_pid = file_name
                .to_str()
                .is_some_and(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()));
            if !is_pid {
                continue;
            }
            match read_comm(&entry.path().join("comm")) {
                Ok(name) => names.push(name),
                Err(error) if gone(&error) => {}
                Err(error) => return Err(io_error(&error)),
            }
        }
        Ok(names)
    }

    fn read_comm(path: &Path) -> io::Result<String> {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(COMM_READ_BYTES)
            .read_to_end(&mut bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn gone(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(ESRCH)
    }

    fn io_error(error: &io::Error) -> CollectorError {
        match error.kind() {
            io::ErrorKind::PermissionDenied => super::error(
                CollectorErrorCode::PermissionDenied,
                "process information is not readable by this identity",
                false,
            ),
            io::ErrorKind::NotFound => {
                super::error(CollectorErrorCode::NotFound, "/proc is not mounted", false)
            }
            _ => super::error(CollectorErrorCode::Internal, "cannot read /proc", true),
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
mod platform {
    use std::time::Instant;

    use openvibes_core::CollectorError;
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

    // sysinfo gives no per-process failure or deadline; the caller checks the
    // deadline afterwards and treats an empty list as a failure.
    pub(super) fn names(_deadline: Instant) -> Result<Vec<String>, CollectorError> {
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing(),
        );
        Ok(system
            .processes()
            .values()
            .map(|process| process.name().to_string_lossy().into_owned())
            .collect())
    }
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
mod platform {
    use std::time::Instant;

    use openvibes_core::{CollectorError, CollectorErrorCode};

    pub(super) fn names(_deadline: Instant) -> Result<Vec<String>, CollectorError> {
        Err(super::error(
            CollectorErrorCode::Unsupported,
            "process collection is not supported on this OS",
            false,
        ))
    }
}

#[cfg(test)]
mod tests;
