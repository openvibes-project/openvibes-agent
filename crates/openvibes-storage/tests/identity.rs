//! Host identity persistence: survives restart, rotates atomically, clears on
//! revocation, and reports damage instead of silently forgetting the identity.

use std::{
    fs,
    path::{Path, PathBuf},
};

use openvibes_core::{Identifier, ResourceLimits};
use openvibes_storage::{IdentityStore, RuleStore, StorageError, StoredIdentity};
use rusqlite::Connection;
use zeroize::Zeroizing;

fn identity(generation: u8) -> StoredIdentity {
    StoredIdentity {
        agent_id: Identifier::new("agent.1").unwrap(),
        key_pem: Zeroizing::new(format!("KEY {generation}")),
        certificate_chain_pem: vec![format!("LEAF {generation}"), "CA".into()],
        expires_at_unix_ms: i64::from(generation) * 1_000,
    }
}

/// Fresh store path unique to one test.
fn path(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("storage-identity");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{test}.sqlite"));
    let _ = fs::remove_file(&path);
    path
}

fn open(path: &Path) -> IdentityStore {
    IdentityStore::open(path, ResourceLimits::V1).unwrap()
}

#[test]
fn identity_survives_restart_rotates_and_clears() {
    let path = path("lifecycle");
    let mut store = open(&path);
    assert_eq!(store.get(), Ok(None));
    store.replace(&identity(1)).unwrap();
    drop(store);

    let mut store = open(&path);
    assert_eq!(store.get(), Ok(Some(identity(1))));
    store.replace(&identity(2)).unwrap();
    assert_eq!(store.get(), Ok(Some(identity(2))));
    store.clear().unwrap();
    drop(store);
    assert_eq!(open(&path).get(), Ok(None));
}

#[test]
fn rotation_overwrites_the_previous_key_on_disk() {
    let path = path("overwrite");
    let mut store = open(&path);
    store
        .replace(&StoredIdentity {
            key_pem: Zeroizing::new("OLD-SECRET-KEY-MATERIAL".into()),
            ..identity(1)
        })
        .unwrap();
    store.replace(&identity(2)).unwrap();
    drop(store);
    let bytes = fs::read(&path).unwrap();
    let needle = b"OLD-SECRET-KEY-MATERIAL";
    assert!(!bytes.windows(needle.len()).any(|window| window == needle));
}

#[test]
fn invalid_identities_are_rejected() {
    let mut store = open(&path("invalid"));
    let too_long = "x".repeat(ResourceLimits::V1.string_bytes + 1);
    for invalid in [
        StoredIdentity {
            key_pem: Zeroizing::new(String::new()),
            ..identity(1)
        },
        StoredIdentity {
            certificate_chain_pem: Vec::new(),
            ..identity(1)
        },
        StoredIdentity {
            certificate_chain_pem: vec![too_long],
            ..identity(1)
        },
        StoredIdentity {
            expires_at_unix_ms: -1,
            ..identity(1)
        },
    ] {
        assert_eq!(store.replace(&invalid), Err(StorageError::InvalidIdentity));
    }
    assert_eq!(store.get(), Ok(None));
}

#[test]
fn damaged_records_are_errors_not_missing_identities() {
    for (name, damage) in [
        ("agent", "UPDATE identity SET agent_id = 'bad id'"),
        ("chain", "UPDATE identity SET chain_json = 'not json'"),
        ("empty-chain", "UPDATE identity SET chain_json = '[]'"),
        ("key", "UPDATE identity SET key_pem = ''"),
    ] {
        let path = path(name);
        open(&path).replace(&identity(1)).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute(damage, [])
            .unwrap();
        assert_eq!(open(&path).get(), Err(StorageError::Corrupt), "{name}");
    }
}

#[test]
fn debug_output_redacts_the_key() {
    let debug = format!("{:?}", identity(1));
    assert!(!debug.contains("KEY 1"), "{debug}");
    assert!(debug.contains("agent.1"));
}

#[test]
fn identity_database_is_its_own_kind() {
    let path = path("kind");
    drop(open(&path));
    assert_eq!(
        RuleStore::open(&path, ResourceLimits::V1).err(),
        Some(StorageError::Corrupt)
    );
}
