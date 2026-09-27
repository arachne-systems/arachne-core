//! Stored formats are versioned: supported legacy formats migrate; unknown or
//! newer formats fail with FormatNotSupported and a clear message.
use arachne_runtime::{
    Client, ClientConfig, ErrorCode, MemoryProvider, Network, RestoredWorkspace, SqliteProvider,
    StorageConfig,
};
use arachne_store::StorageProvider;

mod common;

fn open(storage: StorageConfig) -> std::sync::Arc<Client> {
    Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([81; 32]).into()),
        transport: Default::default(),
        storage: Some((storage).into()),
    })
    .unwrap()
}

#[test]
fn runtime_records_carry_their_format_and_refuse_others() {
    let provider = MemoryProvider::default();
    let client = open(StorageConfig::memory(&provider));
    let created = client.create_workspace("Owner", None).unwrap();
    client.close().unwrap();
    let workspace = created.workspace;
    // Stored values carry a one-byte tag (0: the whole value).
    assert_eq!(
        provider.value((workspace).to_bytes(), b"runtime/format"),
        Some(vec![0, 0, 0, 0, 1])
    );

    for (format, what) in [
        (Some(vec![0, 0, 0, 0, 2]), "newer"),
        (None, "no runtime format"),
        (Some(vec![0, 0, 0, 1]), "invalid"),
    ] {
        let original = provider.value((workspace).to_bytes(), b"runtime/format");
        provider.tamper((workspace).to_bytes(), b"runtime/format", format.as_deref());
        let client = open(StorageConfig::memory(&provider));
        let error = client.restore_workspace(workspace, None).unwrap_err();
        assert_eq!(error.code(), ErrorCode::FormatNotSupported, "{error:?}");
        assert!(error.message().contains(what), "{error:?}");
        client.close().unwrap();
        provider.tamper(
            (workspace).to_bytes(),
            b"runtime/format",
            original.as_deref(),
        );
    }
    let client = open(StorageConfig::memory(&provider));
    assert!(matches!(
        client.restore_workspace(workspace, None).unwrap(),
        RestoredWorkspace::Active(_)
    ));
    client.close().unwrap();
}

#[test]
fn original_runtime_records_restore_and_migrate_before_use() {
    let provider = MemoryProvider::default();
    let storage = StorageConfig::memory(&provider);
    let client = open(storage.clone());
    let created = client.create_workspace("Legacy owner", None).unwrap();
    let workspace = created.workspace;
    client.close().unwrap();

    // Rebuild the original flat record layout: no runtime/format or endpoint
    // record and no one-byte value tags.
    let mut store = provider.open(workspace.to_bytes()).unwrap().unwrap();
    let keys = store.keys(b"");
    let values = keys
        .into_iter()
        .map(|name| {
            let value = store.get(&name).unwrap().unwrap();
            if name == b"runtime/format" || name == b"runtime/endpoint" {
                (name, None)
            } else {
                assert_eq!(value.first(), Some(&0));
                (name, Some(value[1..].to_vec()))
            }
        })
        .collect::<Vec<_>>();
    let changes = values
        .iter()
        .map(|(name, value)| (name.as_slice(), value.as_deref()))
        .collect::<Vec<_>>();
    let revision = store.revision();
    store.commit(revision, &changes).unwrap();
    let legacy_anchor = store.freshness();
    drop(store);

    let restored = open(storage);
    assert!(matches!(
        restored
            .restore_workspace(workspace, Some(legacy_anchor))
            .unwrap(),
        RestoredWorkspace::Active(_)
    ));
    assert_ne!(restored.record_freshness().unwrap(), legacy_anchor);
    let migrated = provider.open(workspace.to_bytes()).unwrap().unwrap();
    assert_eq!(
        migrated.get(b"runtime/format").unwrap().unwrap().as_slice(),
        [0, 0, 0, 0, 1]
    );
    assert!(migrated.get(b"runtime/endpoint").unwrap().is_some());
    restored.close().unwrap();
}

#[test]
fn a_newer_store_file_format_is_refused_with_its_code() {
    let directory = common::directory();
    let root = [82; 32];
    let client = open(StorageConfig::sqlite(directory.path(), root));
    let created = client.create_workspace("Owner", None).unwrap();
    let anchor = client.record_freshness().unwrap();
    client.close().unwrap();
    let path = SqliteProvider::new(directory.path(), root).path((created.workspace).to_bytes());
    // A later build wrote this file.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("PRAGMA user_version=99;").unwrap();
    drop(connection);
    let client = open(StorageConfig::sqlite(directory.path(), root));
    let error = client
        .restore_workspace(created.workspace, Some(anchor))
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::FormatNotSupported, "{error:?}");
    assert!(error.message().contains("99"), "{error:?}");
    client.close().unwrap();
    directory.close().unwrap();
}
