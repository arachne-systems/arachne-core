//! A5 item 5: stored formats are versioned. There are no legacy readers: an
//! unknown or newer format fails with FormatNotSupported and a clear message.
use arachne_runtime::{
    Client, ClientConfig, ErrorCode, MemoryProvider, Network, RestoredWorkspace, SqliteProvider,
    StorageConfig,
};

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
        (Some(vec![0, 0, 1]), "invalid"),
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
fn a_newer_store_file_format_is_refused_with_its_code() {
    let directory = common::directory();
    let root = [82; 32];
    let client = open(StorageConfig::sqlite(directory.path(), root));
    let created = client.create_workspace("Owner", None).unwrap();
    client.close().unwrap();
    let path = SqliteProvider::new(directory.path(), root).path((created.workspace).to_bytes());
    // A later build wrote this file.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("PRAGMA user_version=99;").unwrap();
    drop(connection);
    let client = open(StorageConfig::sqlite(directory.path(), root));
    let error = client
        .restore_workspace(created.workspace, None)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::FormatNotSupported, "{error:?}");
    assert!(error.message().contains("99"), "{error:?}");
    client.close().unwrap();
    directory.close().unwrap();
}
