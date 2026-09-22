//! State-path hardening on Unix: private creation, rejection of links, loose
//! permissions, traversal, and swappable ancestors.
#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use openvibes_core::ResourceLimits;
use openvibes_storage::{RuleStore, SqliteQueue, StorageError, prepare_state_dir};

/// Fresh, empty private scratch directory unique to one test.
fn scratch(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("storage-paths")
        .join(test);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

#[test]
fn creates_a_private_directory_and_private_database_files() {
    let state = scratch("create").join("state");
    prepare_state_dir(&state).unwrap();
    assert_eq!(mode(&state), 0o700);
    // Validating an existing, correct directory succeeds.
    prepare_state_dir(&state).unwrap();

    drop(SqliteQueue::open(&state.join("queue.sqlite"), ResourceLimits::V1).unwrap());
    drop(RuleStore::open(&state.join("rules.sqlite"), ResourceLimits::V1).unwrap());
    assert_eq!(mode(&state.join("queue.sqlite")), 0o600);
    assert_eq!(mode(&state.join("rules.sqlite")), 0o600);
}

#[test]
fn rejects_relative_traversing_linked_and_non_directory_paths() {
    let root = scratch("reject");
    let real = root.join("real");
    prepare_state_dir(&real).unwrap();
    symlink(&real, root.join("link")).unwrap();
    fs::write(root.join("file"), b"").unwrap();

    for path in [
        PathBuf::from("relative/state"),
        root.join("real/../real"),
        root.join("link"),
        root.join("file"),
    ] {
        assert_eq!(
            prepare_state_dir(&path),
            Err(StorageError::InsecurePath),
            "{path:?}"
        );
    }
}

#[test]
fn rejects_a_directory_other_users_can_access() {
    let state = scratch("loose").join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(prepare_state_dir(&state), Err(StorageError::InsecurePath));
    // Rejected, never silently repaired.
    assert_eq!(mode(&state), 0o750);
}

#[test]
fn rejects_an_ancestor_others_can_rename_entries_in() {
    let shared = scratch("ancestor").join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        prepare_state_dir(&shared.join("state")),
        Err(StorageError::InsecurePath)
    );
    // The sticky bit stops other users renaming our entries, as in /tmp.
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
    prepare_state_dir(&shared.join("state")).unwrap();
}

#[test]
fn rejects_hard_linked_database_files() {
    let state = scratch("hardlink").join("state");
    prepare_state_dir(&state).unwrap();
    let queue = state.join("queue.sqlite");
    drop(SqliteQueue::open(&queue, ResourceLimits::V1).unwrap());
    fs::hard_link(&queue, state.join("alias.sqlite")).unwrap();
    assert_eq!(
        SqliteQueue::open(&queue, ResourceLimits::V1).err(),
        Some(StorageError::InsecurePath)
    );
}
