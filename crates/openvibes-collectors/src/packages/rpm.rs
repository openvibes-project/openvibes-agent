//! RPM 4.16+ SQLite database: each `Packages.blob` is one RPM header
//! (`il`, `dl`, `il` index entries of tag/type/offset/count, `dl` data bytes).

use std::{path::Path, time::Instant};

use openvibes_core::{CollectorError, CollectorErrorCode, InstalledPackage, PackageManager};
use rusqlite::{Connection, OpenFlags};

use super::error;

const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_EPOCH: u32 = 1003;
const TAG_VENDOR: u32 = 1011;
const TAG_ARCH: u32 = 1022;
const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
/// RPM's own ceilings for one header's index entries and data bytes.
const MAX_ENTRIES: usize = 0x0000_ffff;
const MAX_DATA: usize = 256 * 1024 * 1024;
/// Longest string field taken from a header.
const MAX_FIELD: usize = 4_096;

pub(super) fn read(
    path: &Path,
    deadline: Instant,
) -> Result<Vec<InstalledPackage>, CollectorError> {
    let unreadable = |_| {
        error(
            CollectorErrorCode::PermissionDenied,
            "cannot read the RPM database",
            false,
        )
    };
    let uri = format!("file:{}?{}", path.display(), read_only_mode(path));
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(uri, flags).map_err(unreadable)?;
    // Schema-embedded SQL (views, triggers) never runs functions for us.
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(unreadable)?;
    connection
        .pragma_update(None, "query_only", true)
        .map_err(unreadable)?;
    let mut statement = connection
        .prepare("SELECT blob FROM Packages")
        .map_err(|_| malformed())?;
    let mut rows = statement.query([]).map_err(unreadable)?;
    let mut packages = Vec::new();
    while let Some(row) = rows.next().map_err(|_| malformed())? {
        if Instant::now() > deadline {
            return Err(error(
                CollectorErrorCode::TimedOut,
                "package scan exceeded its deadline",
                true,
            ));
        }
        let blob = row
            .get_ref(0)
            .and_then(|value| Ok(value.as_blob()?))
            .map_err(|_| malformed())?;
        let package = parse_header(blob).ok_or_else(malformed)?;
        if package.name != "gpg-pubkey" {
            packages.push(package);
        }
    }
    Ok(packages)
}

/// URI parameters that keep SQLite from creating or writing any file next to
/// the database. A plain `mode=ro` reader of a WAL database creates the
/// `-wal` and `-shm` files and writes read marks into `-shm` whenever the
/// directory is writable (as root). So: while a WAL connection is active
/// (`-shm` or `-wal` exists) read its shared memory without writing it;
/// with a rollback journal, a plain read-only open writes nothing; with
/// neither, no connection is writing and the file is read as immutable. A
/// writer that starts during an immutable read may make that read fail or
/// be inconsistent; the next scan reads again.
fn read_only_mode(path: &Path) -> &'static str {
    let sibling = |suffix: &str| {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        Path::new(&name).exists()
    };
    if sibling("-shm") || sibling("-wal") {
        "mode=ro&readonly_shm=1"
    } else if sibling("-journal") {
        "mode=ro"
    } else {
        "mode=ro&immutable=1"
    }
}

fn malformed() -> CollectorError {
    error(
        CollectorErrorCode::InvalidData,
        "the RPM database holds a malformed header",
        false,
    )
}

/// Parses one header, or `None` if it lacks a name or version or any field
/// it holds is malformed. Every offset is bounds-checked against the header itself.
pub(super) fn parse_header(blob: &[u8]) -> Option<InstalledPackage> {
    let be32 = |at: usize| -> Option<u32> {
        Some(u32::from_be_bytes(
            blob.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    };
    let entries = usize::try_from(be32(0)?).ok()?;
    let data_len = usize::try_from(be32(4)?).ok()?;
    if entries > MAX_ENTRIES || data_len > MAX_DATA {
        return None;
    }
    let data_start = 8 + entries * 16;
    if blob.len() != data_start.checked_add(data_len)? {
        return None;
    }
    let data = &blob[data_start..];
    // The (type, data offset) of `tag`'s index entry.
    let find = |tag: u32| -> Option<(u32, usize)> {
        let index = (0..entries).find(|index| be32(8 + index * 16) == Some(tag))?;
        let at = 8 + index * 16;
        Some((be32(at + 4)?, usize::try_from(be32(at + 8)?).ok()?))
    };
    // Outer `None`: the field is malformed. Inner `None`: it is absent.
    let string = |tag: u32| -> Option<Option<String>> {
        let Some((kind, offset)) = find(tag) else {
            return Some(None);
        };
        let rest = data.get(offset..)?;
        let bytes = &rest[..rest.iter().position(|&byte| byte == 0)?];
        let value = std::str::from_utf8(bytes).ok()?;
        let valid = kind == TYPE_STRING && !value.is_empty() && value.len() <= MAX_FIELD;
        valid.then(|| Some(value.to_owned()))
    };
    let epoch = match find(TAG_EPOCH) {
        None => None,
        Some((kind, offset)) => {
            let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
            if kind != TYPE_INT32 {
                return None;
            }
            Some(u32::from_be_bytes(bytes))
        }
    };
    Some(InstalledPackage {
        manager: PackageManager::Rpm,
        name: string(TAG_NAME)??,
        version: string(TAG_VERSION)??,
        release: string(TAG_RELEASE)?,
        epoch,
        arch: string(TAG_ARCH)?,
        vendor: string(TAG_VENDOR)?,
        source: None,
        source_version: None,
    })
}
