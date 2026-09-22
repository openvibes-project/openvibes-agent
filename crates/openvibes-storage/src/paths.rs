use std::{
    fs, io,
    path::{Component, Path},
};

use crate::db::StorageError;

/// Creates `path` as a private agent-owned state directory, or validates an
/// existing one. Call before opening any database inside it.
///
/// `path` must be absolute without `..` components and must not be a symlink or
/// reparse point. On Unix the directory must be owned by the effective user
/// with no group or other permissions (created as `0700`), and no ancestor may
/// be writable by another user unless it is sticky, so the directory cannot be
/// swapped out. An insecure existing directory is rejected, never repaired.
pub fn prepare_state_dir(path: &Path) -> Result<(), StorageError> {
    if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
        return Err(StorageError::InsecurePath);
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_private_dir(path).map_err(|_| StorageError::Unavailable)?;
        }
        Err(_) => return Err(StorageError::Unavailable),
        Ok(_) => {}
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| StorageError::Unavailable)?;
    if !metadata.file_type().is_dir() {
        return Err(StorageError::InsecurePath);
    }
    platform::check_dir(path, &metadata)
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    // The umask can only remove bits, so the result is never looser than 0700.
    fs::DirBuilder::new().mode(0o700).create(path)
}

// ponytail: Windows relies on the installer (Milestone 6) setting a
// SYSTEM/Administrators-only ACL; std cannot inspect or set ACLs.
#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
pub(crate) mod platform {
    use std::{fs, os::unix::fs::MetadataExt, path::Path};

    use crate::db::StorageError;

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    pub(crate) fn check_dir(path: &Path, metadata: &fs::Metadata) -> Result<(), StorageError> {
        if metadata.uid() != euid() || metadata.mode() & 0o077 != 0 {
            return Err(StorageError::InsecurePath);
        }
        for ancestor in path.ancestors().skip(1) {
            let metadata = fs::metadata(ancestor).map_err(|_| StorageError::Unavailable)?;
            let trusted_owner = metadata.uid() == 0 || metadata.uid() == euid();
            let others_can_rename = metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0;
            if !trusted_owner || others_can_rename {
                return Err(StorageError::InsecurePath);
            }
        }
        Ok(())
    }

    /// Rejects an existing database file that is a link or not ours.
    pub(crate) fn check_file_before_open(path: &Path) -> Result<(), StorageError> {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    || metadata.nlink() > 1
                    || metadata.uid() != euid() =>
            {
                Err(StorageError::InsecurePath)
            }
            _ => Ok(()),
        }
    }

    /// Restricts a database file to its owner; SQLite gives journal files the
    /// database file's permissions.
    pub(crate) fn restrict_file(path: &Path) -> Result<(), StorageError> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| StorageError::Unavailable)
    }
}

#[cfg(not(unix))]
pub(crate) mod platform {
    use std::{fs, path::Path};

    use crate::db::StorageError;

    pub(crate) fn check_dir(_: &Path, _: &fs::Metadata) -> Result<(), StorageError> {
        Ok(())
    }

    pub(crate) fn check_file_before_open(_: &Path) -> Result<(), StorageError> {
        Ok(())
    }

    pub(crate) fn restrict_file(_: &Path) -> Result<(), StorageError> {
        Ok(())
    }
}
