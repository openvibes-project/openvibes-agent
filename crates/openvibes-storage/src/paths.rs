use std::{
    fs::{self, File},
    io,
    path::{Component, Path},
};

use crate::db::StorageError;

/// Creates `path` as a private agent-owned state directory, or validates an
/// existing one. Call before opening any database inside it.
///
/// `path` must be absolute without `..` components and must not be a symlink or
/// reparse point. On Unix the directory must be owned by the effective user
/// with no group or other permissions (created as `0700`), and only root and
/// the effective user may be able to change what the path resolves to (see
/// [`open_input_file`]), so the directory cannot be swapped out. An insecure
/// existing directory is rejected, never repaired.
pub fn prepare_state_dir(path: &Path) -> Result<(), StorageError> {
    if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
        return Err(StorageError::InsecurePath);
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Never create anything through a path another user controls.
            if let Some(parent) = path.parent() {
                platform::check_parent(parent)?;
            }
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

/// Opens a file the agent trusts but does not own, such as its configuration,
/// CA bundle, enrollment token, or a provisioned rule bundle. `None` if
/// nothing exists at `path`.
///
/// On Unix only root and the effective user may be able to change what the
/// path resolves to: every entry on the way, including the targets of links,
/// must be owned by one of them; no directory may let other users rename its
/// entries (unless sticky), and no file may be writable by group or others.
/// The file must be a regular file; it is opened without blocking, so a FIFO
/// or device is refused instead of hanging the agent. A `secret` file must
/// not be readable by others either. Violations are
/// [`StorageError::InsecurePath`]; other failures [`StorageError::Unavailable`].
pub fn open_input_file(path: &Path, secret: bool) -> Result<Option<File>, StorageError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(StorageError::Unavailable),
        Ok(_) => {}
    }
    platform::open_input(path, secret).map(Some)
}

/// Checks that `path` is a directory the agent may write files into on
/// behalf of an operator: on Unix, under the same rules as
/// [`open_input_file`], so no other user can redirect the writes.
pub fn check_output_dir(path: &Path) -> Result<(), StorageError> {
    fs::symlink_metadata(path).map_err(|_| StorageError::Unavailable)?;
    platform::check_output_dir(path)
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
    use std::{
        fs::{self, File},
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
    };

    use rustix::fs::{Mode, OFlags};

    use crate::db::StorageError;

    /// Longest chain of links followed, as Linux's `ELOOP` limit.
    const MAX_LINKS: u32 = 40;

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    pub(crate) fn check_dir(path: &Path, metadata: &fs::Metadata) -> Result<(), StorageError> {
        if metadata.uid() != euid() || metadata.mode() & 0o077 != 0 {
            return Err(StorageError::InsecurePath);
        }
        check_chain(path).map(drop)
    }

    pub(crate) fn check_parent(path: &Path) -> Result<(), StorageError> {
        check_chain(path).map(drop)
    }

    /// Refuses an entry another user could replace or rewrite: one not owned
    /// by root or the effective user, a directory others may rename entries
    /// in (unless sticky), or a file group or others may write.
    fn check_entry(metadata: &fs::Metadata) -> Result<(), StorageError> {
        let mode = metadata.mode();
        let others_write = mode & 0o022 != 0;
        let file_type = metadata.file_type();
        let loose = if file_type.is_symlink() {
            // A link's own mode means nothing; its owner and directory count.
            false
        } else if file_type.is_dir() {
            others_write && mode & 0o1000 == 0
        } else {
            others_write
        };
        if (metadata.uid() == 0 || metadata.uid() == euid()) && !loose {
            Ok(())
        } else {
            Err(StorageError::InsecurePath)
        }
    }

    /// Checks every entry `path` passes through, returning the resolved path.
    /// Entries are examined without following links, since in a sticky
    /// directory a link's owner can still replace it; each link's target is
    /// checked the same way, so no entry anywhere along the resolution is
    /// left to another user.
    fn check_chain(path: &Path) -> Result<PathBuf, StorageError> {
        let written = std::path::absolute(path).map_err(|_| StorageError::Unavailable)?;
        check_written(&written, 0)?;
        fs::canonicalize(&written).map_err(|_| StorageError::Unavailable)
    }

    fn check_written(path: &Path, links: u32) -> Result<(), StorageError> {
        for entry in path.ancestors() {
            let metadata = fs::symlink_metadata(entry).map_err(|_| StorageError::Unavailable)?;
            check_entry(&metadata)?;
            if metadata.file_type().is_symlink() {
                if links >= MAX_LINKS {
                    return Err(StorageError::InsecurePath);
                }
                let target = fs::read_link(entry).map_err(|_| StorageError::Unavailable)?;
                let base = entry.parent().unwrap_or_else(|| Path::new("/"));
                check_written(&base.join(target), links + 1)?;
            }
        }
        Ok(())
    }

    pub(crate) fn open_input(path: &Path, secret: bool) -> Result<File, StorageError> {
        let resolved = check_chain(path)?;
        let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let file = File::from(
            rustix::fs::open(&resolved, flags, Mode::empty())
                .map_err(|_| StorageError::Unavailable)?,
        );
        // Checked again on the open file: the path may have changed since.
        let metadata = file.metadata().map_err(|_| StorageError::Unavailable)?;
        if !metadata.file_type().is_file() || (secret && metadata.mode() & 0o004 != 0) {
            return Err(StorageError::InsecurePath);
        }
        check_entry(&metadata)?;
        Ok(file)
    }

    pub(crate) fn check_output_dir(path: &Path) -> Result<(), StorageError> {
        let resolved = check_chain(path)?;
        let metadata = fs::metadata(resolved).map_err(|_| StorageError::Unavailable)?;
        if !metadata.is_dir() {
            return Err(StorageError::InsecurePath);
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

// ponytail: Windows checks no ownership or ACLs (see `create_private_dir`).
#[cfg(not(unix))]
pub(crate) mod platform {
    use std::{
        fs::{self, File},
        path::Path,
    };

    use crate::db::StorageError;

    pub(crate) fn check_dir(_: &Path, _: &fs::Metadata) -> Result<(), StorageError> {
        Ok(())
    }

    pub(crate) fn check_parent(_: &Path) -> Result<(), StorageError> {
        Ok(())
    }

    pub(crate) fn open_input(path: &Path, _secret: bool) -> Result<File, StorageError> {
        let file = File::open(path).map_err(|_| StorageError::Unavailable)?;
        let metadata = file.metadata().map_err(|_| StorageError::Unavailable)?;
        if !metadata.is_file() {
            return Err(StorageError::InsecurePath);
        }
        Ok(file)
    }

    pub(crate) fn check_output_dir(path: &Path) -> Result<(), StorageError> {
        let metadata = fs::metadata(path).map_err(|_| StorageError::Unavailable)?;
        if !metadata.is_dir() {
            return Err(StorageError::InsecurePath);
        }
        Ok(())
    }

    pub(crate) fn check_file_before_open(_: &Path) -> Result<(), StorageError> {
        Ok(())
    }

    pub(crate) fn restrict_file(_: &Path) -> Result<(), StorageError> {
        Ok(())
    }
}
