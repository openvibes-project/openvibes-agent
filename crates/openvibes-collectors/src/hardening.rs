//! Hardening facts (protocol P19, platform spec
//! `2026-10-09-hardening-rules-design.md`): how the host is configured, for
//! the hardening rule sets. Run by the root-facts helper
//! (`openvibes-agent-facts`) as root, with no input, and never runs a
//! program: every value comes from reading a file under `root` (`/` on a
//! host, a scratch directory in tests).
//!
//! Every catalog key of a source that could be read is emitted, a setting
//! that is not configured as `""` or `-1` (`vectors/fact-catalog.json`). A
//! source that cannot be read gives no facts and one error whose collector
//! is `hardening.<source>`; its rules are unavailable, never false.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use openvibes_core::{CollectorError, CollectorErrorCode, Fact, FactValue, Identifier};

mod accounts;
mod audit;
mod files;
mod kernel;
mod login;
mod mounts;
mod services;
mod sshd;
mod sysctl;

/// The source every hardening fact names.
const SOURCE: &str = "hardening";
/// Largest file read: real configuration files are a few KiB.
const MAX_FILE: u64 = 1024 * 1024;
/// Longest string value kept (the contract's general string limit).
const MAX_STRING: usize = 4_096;
/// Most items in a string-list fact.
const MAX_LIST: usize = 10_000;

/// What one run read.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Hardening {
    /// Facts, each key at most once.
    pub facts: Vec<Fact>,
    /// One error per source that could not be read.
    pub errors: Vec<CollectorError>,
}

/// Reads every hardening source under `root` (`/` on a host).
#[must_use]
pub fn collect_hardening(root: &Path) -> Hardening {
    let mut out = Out {
        root: root.to_path_buf(),
        hardening: Hardening::default(),
    };
    os(&mut out);
    sshd::collect(&mut out);
    sysctl::collect(&mut out);
    files::collect(&mut out);
    mounts::collect(&mut out);
    services::collect(&mut out);
    login::collect(&mut out);
    accounts::collect(&mut out);
    kernel::collect(&mut out);
    audit::collect(&mut out);
    lsm(&mut out);
    out.hardening
}

/// The collection under way: where to read, and what was found.
pub(crate) struct Out {
    root: PathBuf,
    hardening: Hardening,
}

impl Out {
    /// `path` (absolute, as on the host) below the collection root.
    pub(crate) fn path(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    /// A small text file, bounded, or why not.
    pub(crate) fn read(&self, path: &str) -> Result<String, CollectorErrorCode> {
        read_bounded(&self.path(path))
    }

    pub(crate) fn string(&mut self, key: &str, value: &str) {
        let mut end = value.len().min(MAX_STRING);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        self.push(key, FactValue::String(value[..end].replace('\0', "")));
    }

    pub(crate) fn int(&mut self, key: &str, value: i64) {
        self.push(key, FactValue::Integer(value));
    }

    pub(crate) fn bool(&mut self, key: &str, value: bool) {
        self.push(key, FactValue::Boolean(value));
    }

    /// A string list, sorted, unique, empty items dropped, capped.
    pub(crate) fn list(&mut self, key: &str, values: impl IntoIterator<Item = String>) {
        self.list_len(key, values);
    }

    /// A list and `<key>.count`, its length before the cap (P19: a rule
    /// checks `accounts.uid0.count == 1` without listing names).
    pub(crate) fn counted_list(&mut self, key: &str, values: impl IntoIterator<Item = String>) {
        let count = self.list_len(key, values);
        self.int(
            &format!("{key}.count"),
            i64::try_from(count).unwrap_or(i64::MAX),
        );
    }

    /// Pushes the list; returns how many unique items it had before the cap.
    fn list_len(&mut self, key: &str, values: impl IntoIterator<Item = String>) -> usize {
        let mut values: Vec<String> = values
            .into_iter()
            .filter(|v| !v.is_empty() && v.len() <= MAX_STRING && !v.contains('\0'))
            .collect();
        values.sort();
        values.dedup();
        let count = values.len();
        values.truncate(MAX_LIST);
        self.push(key, FactValue::StringList(values));
        count
    }

    /// A source that could not be read: no facts, one error.
    pub(crate) fn error(&mut self, source: &str, code: CollectorErrorCode, message: &str) {
        self.hardening.errors.push(CollectorError {
            collector: Identifier::new(format!("{SOURCE}.{source}")).expect("static source id"),
            code,
            message: message.to_owned(),
            retryable: code != CollectorErrorCode::Unsupported,
        });
    }

    fn push(&mut self, key: &str, value: FactValue) {
        self.hardening.facts.push(Fact {
            key: Identifier::new(key).expect("catalog fact key"),
            source: Identifier::new(SOURCE).expect("static collector id"),
            value,
        });
    }
}

pub(crate) fn read_bounded(path: &Path) -> Result<String, CollectorErrorCode> {
    let file = fs::File::open(path).map_err(|e| code(&e))?;
    let mut text = String::new();
    file.take(MAX_FILE + 1)
        .read_to_string(&mut text)
        .map_err(|e| code(&e))?;
    if text.len() as u64 > MAX_FILE {
        return Err(CollectorErrorCode::InvalidData);
    }
    Ok(text)
}

pub(crate) fn code(error: &std::io::Error) -> CollectorErrorCode {
    match error.kind() {
        std::io::ErrorKind::NotFound => CollectorErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => CollectorErrorCode::PermissionDenied,
        std::io::ErrorKind::InvalidData => CollectorErrorCode::InvalidData,
        _ => CollectorErrorCode::Internal,
    }
}

/// A plain non-negative decimal, else -1 (the catalog's "unset").
pub(crate) fn plain_int(value: &str) -> i64 {
    let value = value.trim();
    if !value.is_empty() && value.len() <= 18 && value.bytes().all(|b| b.is_ascii_digit()) {
        value.parse().unwrap_or(-1)
    } else {
        -1
    }
}

/// The `*.conf` (or other `suffix`) files in a directory, sorted by name;
/// none when it does not exist.
pub(crate) fn dir_files(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(suffix))
        })
        .collect();
    files.sort();
    files
}

/// `os.*` from os-release: ID, ID_LIKE (plus ID), VERSION_ID.
fn os(out: &mut Out) {
    let Ok(text) = out
        .read("/etc/os-release")
        .or_else(|_| out.read("/usr/lib/os-release"))
    else {
        out.error("os", CollectorErrorCode::NotFound, "no os-release");
        return;
    };
    let value = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches(['"', '\'']).to_owned())
            .unwrap_or_default()
    };
    let id = value("ID");
    let like: Vec<String> = value("ID_LIKE")
        .split_whitespace()
        .map(str::to_owned)
        .chain([id.clone()])
        .collect();
    out.string("os.id", &id);
    out.list("os.id_like", like);
    out.string("os.version_id", &value("VERSION_ID"));
}

/// `lsm.*`: SELinux and AppArmor state; "disabled" when absent.
fn lsm(out: &mut Out) {
    let selinux = match out
        .read("/sys/fs/selinux/enforce")
        .map(|v| v.trim().to_owned())
    {
        Ok(v) if v == "1" => "enforcing",
        Ok(v) if v == "0" => "permissive",
        _ => "disabled",
    };
    out.string("lsm.selinux", selinux);
    let apparmor = match out.read("/sys/module/apparmor/parameters/enabled") {
        Ok(v) if v.trim() == "Y" => "enabled",
        _ => "disabled",
    };
    out.string("lsm.apparmor", apparmor);
}

#[cfg(all(test, unix))]
mod tests;
