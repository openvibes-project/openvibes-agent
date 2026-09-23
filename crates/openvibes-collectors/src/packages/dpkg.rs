//! dpkg's status database: RFC 822-style stanzas, one per package.

use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use openvibes_core::{CollectorError, CollectorErrorCode, InstalledPackage, PackageManager};

use super::error;

/// Largest status file read; real ones are a few MiB.
const MAX_STATUS_BYTES: u64 = 64 * 1024 * 1024;
/// Longest field value taken from a stanza.
const MAX_FIELD: usize = 4_096;

pub(super) fn read(path: &Path) -> Result<Vec<InstalledPackage>, CollectorError> {
    let mut text = String::new();
    let read =
        File::open(path).and_then(|file| file.take(MAX_STATUS_BYTES + 1).read_to_string(&mut text));
    match read {
        Ok(length) if length as u64 <= MAX_STATUS_BYTES => {}
        Ok(_) => {
            return Err(error(
                CollectorErrorCode::InvalidData,
                "the dpkg status file is too large",
                false,
            ));
        }
        Err(error_) if error_.kind() == io::ErrorKind::PermissionDenied => {
            return Err(error(
                CollectorErrorCode::PermissionDenied,
                "cannot read the dpkg status file",
                false,
            ));
        }
        Err(error_) if error_.kind() == io::ErrorKind::InvalidData => {
            return Err(error(
                CollectorErrorCode::InvalidData,
                "the dpkg status file is not UTF-8",
                false,
            ));
        }
        Err(_) => {
            return Err(error(
                CollectorErrorCode::Internal,
                "cannot read the dpkg status file",
                true,
            ));
        }
    }
    Ok(parse_status(&text))
}

/// Installed packages from a status file; stanzas that are not fully
/// installed or lack a name or version are skipped.
pub(super) fn parse_status(text: &str) -> Vec<InstalledPackage> {
    text.split("\n\n").filter_map(parse_stanza).collect()
}

fn parse_stanza(stanza: &str) -> Option<InstalledPackage> {
    let field = |name: &str| -> Option<&str> {
        stanza.lines().find_map(|line| {
            let value = line.strip_prefix(name)?.strip_prefix(':')?.trim();
            (!value.is_empty() && value.len() <= MAX_FIELD).then_some(value)
        })
    };
    if field("Status")?.split_whitespace().nth(2) != Some("installed") {
        return None;
    }
    let (epoch, rest) = match field("Version")?.split_once(':') {
        Some((epoch, rest)) => (Some(epoch.parse().ok()?), rest),
        None => (None, field("Version")?),
    };
    let (version, release) = match rest.rsplit_once('-') {
        Some((version, release)) => (version, Some(release.to_owned())),
        None => (rest, None),
    };
    if version.is_empty() {
        return None;
    }
    Some(InstalledPackage {
        manager: PackageManager::Dpkg,
        name: field("Package")?.to_owned(),
        version: version.to_owned(),
        release,
        epoch,
        arch: field("Architecture").map(str::to_owned),
        vendor: None,
    })
}
