use super::*;
use arachne_security::{EndpointKey, EndpointSigner, PendingJoin, StorageKey, Workspace};

struct Directory(tempfile::TempDir);
impl Directory {
    fn new() -> Self {
        let mut builder = tempfile::Builder::new();
        builder.prefix("arachne-store-gate-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        Self(builder.tempdir().unwrap())
    }
    fn assert_encrypted(&self, secret: &[u8]) {
        for entry in std::fs::read_dir(self.0.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let bytes = std::fs::read(&path).unwrap();
                assert!(
                    !bytes.windows(secret.len()).any(|w| w == secret),
                    "plaintext marker in {}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn admission_records_commit_together_and_reject_mixed_restoration() {
    let directory = Directory::new();
    let path = directory.0.path().join("workspace.db");
    let root = [7; 32]; // Isolated test fixture, never a runtime default.
    let owner_key = EndpointKey::generate().unwrap();
    let member_key = EndpointKey::generate().unwrap();
    let owner = Workspace::create(&owner_key, "Storage gate admin").unwrap();
    let scope = owner.id();
    let key = StorageKey::derive(&root).unwrap();
    let old = owner.seal(&key).unwrap();
    let (registered, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    let owner = registered.workspace;
    let pending =
        PendingJoin::from_invitation(&invitation, &checkpoint, &member_key, "Storage gate member")
            .unwrap();
    let admitted = owner
        .prepare_admission(member_key.endpoint(), pending.admission_request().unwrap())
        .unwrap();
    let next = admitted.workspace.seal(&key).unwrap();
    let mut store = Store::open(&path, &root, scope).unwrap();
    let marker = b"private-record-marker-never-present-in-sqlite-or-rollback-journal";
    store
        .commit(0, &[(b"state", Some(&old)), (b"private", Some(marker))])
        .unwrap();
    assert!(Store::open(&path, &root, scope).is_err()); // Exclusive ownership.
    let old_cipher: Vec<u8> = store
        .connection
        .query_row(
            "SELECT sealed FROM records WHERE name=?1",
            [b"state"],
            |r| r.get(0),
        )
        .unwrap();
    // The second write aborts in SQLite after the state update has executed.
    store
        .connection
        .execute_batch(
            "CREATE TRIGGER fail_history BEFORE INSERT ON records WHEN NEW.name=X'686973746f7279'
         BEGIN SELECT RAISE(ABORT, 'injected history write failure'); END;",
        )
        .unwrap();
    let changes: &[Change<'_>] = &[
        (b"state", Some(&next)),
        (b"history", Some(&admitted.commit)),
        (b"reply", Some(&admitted.welcome)),
    ];
    assert!(
        store
            .commit(1, changes)
            .unwrap_err()
            .to_string()
            .contains("injected history write failure")
    );
    assert_eq!(store.revision(), 1);
    store
        .connection
        .execute_batch("DROP TRIGGER fail_history")
        .unwrap();
    drop(store);
    let mut store = Store::open(&path, &root, scope).unwrap();
    assert_eq!(store.get(b"state").unwrap().unwrap().as_slice(), old);
    assert!(store.get(b"history").unwrap().is_none());
    assert!(store.get(b"reply").unwrap().is_none());
    assert_eq!(store.commit(1, changes).unwrap(), 2);
    assert!(store.commit(1, changes).is_err());
    drop(store);

    let store = Store::open(&path, &root, scope).unwrap();
    assert_eq!(store.revision(), 2);
    let saved = store.get(b"state").unwrap().unwrap();
    let restored = Workspace::restore(&key, owner_key.endpoint(), scope, &saved).unwrap();
    assert_eq!(restored.member_count(), 2);
    let commit = store.get(b"history").unwrap().unwrap();
    let welcome = store.get(b"reply").unwrap().unwrap();
    let mut proof = pending.join_proof().unwrap();
    proof.apply_add(&admitted.authorization, &commit).unwrap();
    let joined = pending.prepare_workspace(&proof, &welcome).unwrap();
    assert!(proof.matches_workspace(&restored).unwrap());
    assert_eq!(joined.member_count(), 2);
    assert_eq!(store.get(b"private").unwrap().unwrap().as_slice(), marker);
    directory.assert_encrypted(marker);

    // Inspect a real rollback journal while SQLite holds an uncommitted write.
    store
        .connection
        .execute_batch(
            "BEGIN IMMEDIATE; UPDATE records SET sealed=zeroblob(80) WHERE name=X'70726976617465';",
        )
        .unwrap();
    assert!(path.with_file_name("workspace.db-journal").exists());
    directory.assert_encrypted(marker);
    store.connection.execute_batch("ROLLBACK").unwrap();
    assert_eq!(store.get(b"private").unwrap().unwrap().as_slice(), marker);

    // A valid old row alone cannot be mixed into a newer accepted transaction.
    store
        .connection
        .execute(
            "UPDATE records SET sealed=?1 WHERE name=?2",
            params![old_cipher, b"state"],
        )
        .unwrap();
    assert!(store.get(b"state").is_err());
    drop(store);
    assert!(Store::open(&path, &root, scope).is_err());
    directory.0.close().unwrap();
    println!(
        "atomic admission: forced second-write failure, reopen, complete MLS join, stale revision, exclusive owner, journal encryption, and mixed-row rejection passed"
    );
}

#[test]
fn records_grow_incrementally_and_bind_scope_and_key() {
    let directory = Directory::new();
    let path = directory.0.path().join("records.db");
    let root = [9; 32];
    let scope = [3; 32];
    let mut store = Store::open(&path, &root, scope).unwrap();
    // Cross prior reply/history count limits; unchanged ciphertext stays unchanged.
    let mut first = Vec::new();
    for n in 0u64..128 {
        let name = n.to_be_bytes();
        let value = format!("private value {n}");
        store.commit(n, &[(&name, Some(value.as_bytes()))]).unwrap();
        let cipher: Vec<u8> = store
            .connection
            .query_row(
                "SELECT sealed FROM records WHERE name=?1",
                [&0u64.to_be_bytes()],
                |r| r.get(0),
            )
            .unwrap();
        if n == 0 {
            first = cipher;
        } else {
            assert_eq!(cipher, first);
        }
    }
    assert!(
        store
            .commit(128, &[(b"oversize", Some(&vec![0; MAX_RECORD_BYTES + 1]))])
            .is_err()
    );
    assert!(
        store
            .commit(128, &[(b"duplicate", None), (b"duplicate", None)])
            .is_err()
    );
    assert_eq!(store.revision(), 128);
    drop(store);
    assert!(Store::open(&path, &[8; 32], scope).is_err());
    assert!(Store::open(&path, &root, [4; 32]).is_err());
    let mut store = Store::open(&path, &root, scope).unwrap();
    for n in 0u64..128 {
        assert_eq!(
            store.get(&n.to_be_bytes()).unwrap().unwrap().as_slice(),
            format!("private value {n}").as_bytes()
        );
    }
    assert!(store.unseal(1, &1u64.to_be_bytes(), &first).is_err());
    assert!(store.unseal(0, &0u64.to_be_bytes(), &first).is_err());
    store
        .commit(128, &[(&0u64.to_be_bytes(), None), (b"empty", Some(b""))])
        .unwrap();
    drop(store);
    let store = Store::open(&path, &root, scope).unwrap();
    assert!(store.get(&0u64.to_be_bytes()).unwrap().is_none());
    assert_eq!(store.get(b"empty").unwrap().unwrap().len(), 0);
    store
        .connection
        .execute_batch(
            "CREATE TRIGGER sqliteXpoison BEFORE DELETE ON records BEGIN SELECT RAISE(IGNORE); END;",
        )
        .unwrap();
    drop(store);
    assert!(Store::open(&path, &root, scope).is_err());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TRIGGER sqliteXpoison")
        .unwrap();
    drop(connection);
    let mut store = Store::open(&path, &root, scope).unwrap();
    // Missing head never reinitializes an existing file, even if all rows are lost.
    store
        .connection
        .execute_batch("DELETE FROM records; DELETE FROM head;")
        .unwrap();
    assert!(
        store
            .commit(129, &[(b"must-not-resurrect", Some(b"state"))])
            .is_err()
    );
    drop(store);
    assert!(Store::open(&path, &root, scope).is_err());
    directory.0.close().unwrap();
    println!(
        "128 incremental records: unchanged-row preservation, reopen, bounds, key/scope binding, deletion and missing-head rejection passed"
    );
}

#[test]
fn external_freshness_anchor_rejects_a_valid_rolled_back_store() {
    let directory = Directory::new();
    let path = directory.0.path().join("freshness.db");
    let rollback = directory.0.path().join("freshness-old.db");
    let root = [17; 32];
    let scope = [18; 32];
    let mut store = Store::open(&path, &root, scope).unwrap();
    store.commit(0, &[(b"state", Some(b"one"))]).unwrap();
    let anchor = store.freshness();
    drop(store);
    std::fs::copy(&path, &rollback).unwrap();

    let mut store = Store::open(&path, &root, scope).unwrap();
    store.commit(1, &[(b"state", Some(b"two"))]).unwrap();
    let current = store.freshness();
    assert_ne!(current, anchor);
    drop(store);

    std::fs::copy(&rollback, &path).unwrap();
    let rolled_back = Store::open(&path, &root, scope).unwrap();
    assert!(rolled_back.verify_freshness(current).is_err());
    assert!(rolled_back.verify_freshness(anchor).is_ok());
}

#[test]
fn freshness_anchor_has_a_fixed_byte_encoding() {
    let anchor = FreshnessAnchor {
        revision: 0x0102_0304_0506_0708,
        digest: [9; 32],
    };
    let bytes = anchor.to_bytes();
    assert_eq!(bytes.len(), FreshnessAnchor::ENCODED_LEN);
    assert_eq!(bytes[..8], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(bytes[8..], [9; 32]);
    assert_eq!(FreshnessAnchor::from_bytes(&bytes).unwrap(), anchor);
    assert!(FreshnessAnchor::from_bytes(&bytes[..39]).is_err());
    assert!(FreshnessAnchor::from_bytes(&[0; 41]).is_err());
}

fn roundtrip(provider: &dyn StorageProvider) {
    let scope = [21; 32];
    assert!(provider.open(scope).unwrap().is_none());
    let mut storage = provider.create(scope).unwrap();
    assert!(
        provider.create(scope).is_err(),
        "create never replaces a store"
    );
    assert_eq!(storage.revision(), 0);
    storage
        .commit(
            0,
            &[(b"runtime/a", Some(b"one")), (b"runtime/b", Some(b""))],
        )
        .unwrap();
    let anchor = storage.freshness();
    assert_eq!(anchor.revision, 1);
    drop(storage);
    let storage = provider.open(scope).unwrap().expect("store exists");
    assert_eq!(storage.freshness(), anchor);
    assert_eq!(
        storage.keys(b"runtime/"),
        vec![b"runtime/a".to_vec(), b"runtime/b".to_vec()]
    );
    assert_eq!(
        storage.get(b"runtime/a").unwrap().unwrap().as_slice(),
        b"one"
    );
    assert!(storage.get(b"runtime/c").unwrap().is_none());
    assert!(provider.open([22; 32]).unwrap().is_none());
}

#[test]
fn sqlite_and_memory_providers_keep_one_store_per_scope() {
    let directory = Directory::new();
    roundtrip(&SqliteProvider::new(directory.0.path(), [7; 32]));
    roundtrip(&MemoryProvider::default());
}

#[test]
fn memory_provider_injects_commit_and_read_faults() {
    let provider = MemoryProvider::default();
    let mut storage = provider.create([1; 32]).unwrap();
    provider.fail_next_commit();
    assert!(storage.commit(0, &[(b"k", Some(b"v"))]).is_err());
    assert_eq!(storage.revision(), 0);
    storage.commit(0, &[(b"k", Some(b"v"))]).unwrap();
    provider.corrupt_reads(true);
    assert_ne!(storage.get(b"k").unwrap().unwrap().as_slice(), b"v");
    provider.corrupt_reads(false);
    assert_eq!(storage.get(b"k").unwrap().unwrap().as_slice(), b"v");
}

#[test]
fn a_crash_during_creation_leaves_no_file_and_creation_retries() {
    let directory = Directory::new();
    let path = directory.0.path().join("workspace.db");
    let root = [31; 32];
    FAIL_CREATE_AFTER_FILE.with(|fail| fail.set(true));
    assert!(Store::create(&path, &root, [1; 32]).is_err());
    assert!(
        !path.exists(),
        "a failed creation must not leave a store file"
    );
    let mut store = Store::create(&path, &root, [1; 32]).unwrap();
    store.commit(0, &[(b"k", Some(b"v"))]).unwrap();
    drop(store);
    assert!(Store::create(&path, &root, [1; 32]).is_err());
    assert_eq!(
        Store::open_existing(&path, &root, [1; 32])
            .unwrap()
            .get(b"k")
            .unwrap()
            .unwrap()
            .as_slice(),
        b"v"
    );
    // No temporary file stays behind.
    assert_eq!(std::fs::read_dir(directory.0.path()).unwrap().count(), 1);
}

#[test]
fn only_the_supported_store_format_opens() {
    let directory = Directory::new();
    let path = directory.0.path().join("workspace.db");
    let root = [32; 32];
    drop(Store::create(&path, &root, [2; 32]).unwrap());
    let set_version = |version: u32| {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(&format!("PRAGMA user_version={version};"))
            .unwrap();
    };
    let refused = |expected: u32| {
        let error = Store::open_existing(&path, &root, [2; 32])
            .err()
            .expect("refused");
        let format = error
            .downcast_ref::<FormatNotSupported>()
            .unwrap_or_else(|| panic!("not a format error: {error}"));
        assert_eq!(format.found, expected);
        assert_eq!(format.supported, STORE_FORMAT);
        assert!(error.to_string().contains("format"), "{error}");
    };
    set_version(STORE_FORMAT + 1);
    refused(STORE_FORMAT + 1);
    // A store from before format records existed: no legacy reader.
    set_version(0);
    refused(0);
    set_version(STORE_FORMAT);
    Store::open_existing(&path, &root, [2; 32]).unwrap();
}

#[test]
fn the_format_is_bound_into_the_authenticated_head() {
    let directory = Directory::new();
    let path = directory.0.path().join("workspace.db");
    let root = [33; 32];
    drop(Store::create(&path, &root, [3; 32]).unwrap());
    let head: Vec<u8> = Connection::open(&path)
        .unwrap()
        .query_row("SELECT sealed FROM head WHERE id=0", [], |row| row.get(0))
        .unwrap();
    let store = Store::open_existing(&path, &root, [3; 32]).unwrap();
    let plain = store.unseal(0, b"", &head).unwrap();
    assert_eq!(plain[..4], STORE_FORMAT.to_be_bytes());
}
