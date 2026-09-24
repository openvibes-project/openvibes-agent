//! Host identity persistence: survives restart, rotates atomically, clears on
//! revocation, and reports damage instead of silently forgetting the identity.

use std::{
    fs,
    path::{Path, PathBuf},
};

use openvibes_core::{Identifier, ResourceLimits};
use openvibes_storage::{IdentityStore, RuleStore, StorageError, StoredIdentity, install_id};
use rusqlite::Connection;
use zeroize::Zeroizing;

fn identity(generation: u8) -> StoredIdentity {
    StoredIdentity {
        agent_id: Identifier::new("agent.1").unwrap(),
        key_pem: Zeroizing::new(format!("KEY {generation}")),
        certificate_chain_pem: vec![format!("LEAF {generation}"), "CA".into()],
        obtained_at_unix_ms: 0,
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
            obtained_at_unix_ms: -1,
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

#[test]
fn install_id_is_created_once_and_kept() {
    let path = path("install");
    let first = install_id(&path).unwrap();
    assert_eq!(first.as_str().len(), 32);
    assert_eq!(install_id(&path).unwrap(), first);
    assert_ne!(install_id(&self::path("install-other")).unwrap(), first);
}

#[test]
fn a_pending_key_is_kept_per_token_until_enrollment_succeeds() {
    let path = path("pending");
    let mut store = open(&path);
    let token = [1; 32];
    assert_eq!(store.begin_enrollment(token).unwrap(), None);
    store.set_pending_key(token, "PENDING KEY").unwrap();
    drop(store);
    // A restart (or a lost response) finds the same key for the same token.
    let mut store = open(&path);
    assert_eq!(
        store
            .begin_enrollment(token)
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("PENDING KEY")
    );
    assert_eq!(
        store.begin_enrollment([2; 32]).unwrap(),
        None,
        "another token"
    );
    store.adopt_enrolled(&identity(1), token).unwrap();
    assert_eq!(store.get().unwrap(), Some(identity(1)));
    assert_eq!(
        store.begin_enrollment(token).unwrap(),
        None,
        "cleared on success"
    );
}

#[test]
fn revocation_refuses_the_enrollment_token_even_after_renewal() {
    let path = path("refused");
    let mut store = open(&path);
    let token = [3; 32];
    store.adopt_enrolled(&identity(1), token).unwrap();
    store.replace(&identity(2)).unwrap(); // renewal keeps the token record
    assert!(!store.is_refused(token).unwrap());
    store.forget_revoked().unwrap();
    assert_eq!(store.get().unwrap(), None);
    assert!(store.is_refused(token).unwrap());
    assert!(!store.is_refused([4; 32]).unwrap());
    // Expiry is not revocation: clear() refuses nothing.
    store.adopt_enrolled(&identity(3), [5; 32]).unwrap();
    store.clear().unwrap();
    assert!(!store.is_refused([5; 32]).unwrap());
}

#[test]
fn a_version_1_identity_database_is_upgraded_in_place() {
    let path = path("upgrade");
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "PRAGMA application_id = 1331054897;
                 CREATE TABLE identity (
                     slot INTEGER PRIMARY KEY CHECK (slot = 1),
                     agent_id TEXT NOT NULL, key_pem TEXT NOT NULL, chain_json TEXT NOT NULL,
                     obtained_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL
                 ) STRICT;
                 INSERT INTO identity VALUES
                     (1, 'agent.v1', 'KEY', '[\"CERT\"]', 5, 10);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut store = open(&path);
    assert_eq!(
        store.get().unwrap().map(|stored| stored.agent_id),
        Some(openvibes_core::Identifier::new("agent.v1").unwrap())
    );
    // Enrolled before tokens were recorded: revocation refuses nothing.
    store.forget_revoked().unwrap();
    assert_eq!(store.get().unwrap(), None);
}
