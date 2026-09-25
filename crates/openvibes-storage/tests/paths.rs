//! State-path hardening on Unix: private creation, rejection of links, loose
//! permissions, traversal, and swappable ancestors.
#![cfg(unix)]

use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use openvibes_core::ResourceLimits;
use openvibes_storage::{
    RuleStore, SqliteQueue, StorageError, check_output_dir, open_input_file, prepare_state_dir,
};

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

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A directory others can rename entries in: 0777 without the sticky bit.
fn shared(root: &Path) -> PathBuf {
    let shared = root.join("shared");
    fs::create_dir(&shared).unwrap();
    chmod(&shared, 0o777);
    shared
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

#[test]
fn rejects_a_linked_ancestor_whose_target_others_can_swap() {
    // A root-created link such as /var/lib/agent -> /home/alice/real, where
    // alice could rename `real` away: the path as written looks private.
    let root = scratch("linked-ancestor");
    let shared = shared(&root);
    fs::create_dir(shared.join("real")).unwrap();
    symlink(shared.join("real"), root.join("link")).unwrap();
    assert_eq!(
        prepare_state_dir(&root.join("link/state")),
        Err(StorageError::InsecurePath)
    );
    assert!(!shared.join("real/state").exists(), "nothing created");

    // A link into directories only we control is fine (as macOS /var).
    fs::create_dir(root.join("private")).unwrap();
    symlink(root.join("private"), root.join("good")).unwrap();
    prepare_state_dir(&root.join("good/state")).unwrap();
}

#[test]
fn rejects_a_link_chain_through_a_directory_others_can_swap() {
    // link -> shared/hop -> private: the intermediate link is neither on
    // the written nor on the resolved path.
    let root = scratch("link-chain");
    let shared = shared(&root);
    fs::create_dir(root.join("private")).unwrap();
    symlink(root.join("private"), shared.join("hop")).unwrap();
    symlink(shared.join("hop"), root.join("link")).unwrap();
    assert_eq!(
        prepare_state_dir(&root.join("link/state")),
        Err(StorageError::InsecurePath)
    );
    fs::write(root.join("private/agent.toml"), b"x").unwrap();
    assert_eq!(
        open_input_file(&root.join("link/agent.toml"), false).err(),
        Some(StorageError::InsecurePath)
    );
}

fn read(path: &Path, secret: bool) -> Result<Option<String>, StorageError> {
    open_input_file(path, secret).map(|file| {
        file.map(|mut file| {
            let mut text = String::new();
            file.read_to_string(&mut text).unwrap();
            text
        })
    })
}

#[test]
fn input_files_must_be_regular_and_unchangeable_by_others() {
    let root = scratch("input");
    let file = root.join("agent.toml");
    fs::write(&file, "config").unwrap();
    chmod(&file, 0o644);
    assert_eq!(read(&file, false), Ok(Some("config".into())));
    assert_eq!(read(&root.join("absent"), false), Ok(None));

    for loose in [0o664, 0o646] {
        chmod(&file, loose);
        assert_eq!(
            read(&file, false),
            Err(StorageError::InsecurePath),
            "{loose:o}"
        );
    }
    chmod(&file, 0o644);

    // Through a link in a trusted directory (as Kubernetes config maps).
    symlink(&file, root.join("alias.toml")).unwrap();
    assert_eq!(
        read(&root.join("alias.toml"), false),
        Ok(Some("config".into()))
    );

    // In a directory where others could replace it.
    let shared = shared(&root);
    fs::write(shared.join("agent.toml"), "config").unwrap();
    chmod(&shared.join("agent.toml"), 0o644);
    assert_eq!(
        read(&shared.join("agent.toml"), false),
        Err(StorageError::InsecurePath)
    );

    // Not a regular file.
    assert_eq!(read(&root, false), Err(StorageError::InsecurePath));
}

#[test]
fn a_fifo_is_refused_without_blocking() {
    // A blocking open of a FIFO waits for a writer forever, hanging the
    // agent's single loop.
    let root = scratch("fifo");
    let fifo = root.join("bundle.json");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert_eq!(read(&fifo, false), Err(StorageError::InsecurePath));
    // A device, too (it is also writable by everyone).
    assert_eq!(
        read(Path::new("/dev/null"), false),
        Err(StorageError::InsecurePath)
    );
}

#[test]
fn a_secret_must_not_be_readable_by_others() {
    let root = scratch("secret");
    let token = root.join("token");
    fs::write(&token, "one-time").unwrap();
    chmod(&token, 0o644);
    assert_eq!(read(&token, true), Err(StorageError::InsecurePath));
    assert_eq!(read(&token, false), Ok(Some("one-time".into())));
    for private in [0o600, 0o640] {
        chmod(&token, private);
        assert_eq!(
            read(&token, true),
            Ok(Some("one-time".into())),
            "{private:o}"
        );
    }
}

#[test]
fn output_directories_must_not_be_redirectable_by_others() {
    let root = scratch("output");
    check_output_dir(&root).unwrap();
    let shared = shared(&root);
    assert_eq!(check_output_dir(&shared), Err(StorageError::InsecurePath));
    fs::create_dir(shared.join("out")).unwrap();
    symlink(shared.join("out"), root.join("out")).unwrap();
    assert_eq!(
        check_output_dir(&root.join("out")),
        Err(StorageError::InsecurePath),
        "a link into a directory others can swap"
    );
    // Sticky, as /tmp: others cannot rename our entries.
    chmod(&shared, 0o1777);
    check_output_dir(&shared).unwrap();
    check_output_dir(&root.join("out")).unwrap();

    fs::write(root.join("file"), b"").unwrap();
    assert_eq!(
        check_output_dir(&root.join("file")),
        Err(StorageError::InsecurePath)
    );
    assert_eq!(
        check_output_dir(&root.join("missing")),
        Err(StorageError::Unavailable)
    );
}
