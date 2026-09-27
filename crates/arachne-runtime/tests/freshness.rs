//! A5 item 6 / B9: with monotonic anchor storage, core saves the freshness
//! anchor with every commit and restore requires it.
use std::sync::Arc;

use arachne_runtime::{
    Client, ClientConfig, ErrorCode, MemoryAnchors, Network, RestoredWorkspace, SqliteProvider,
    StorageConfig,
};

mod common;

fn open(storage: StorageConfig) -> std::sync::Arc<Client> {
    Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([91; 32]).into()),
        transport: Default::default(),
        storage: Some((storage).into()),
    })
    .unwrap()
}

fn publish(client: &Client, workspace: [u8; 32], id: u8) -> arachne_runtime::ClientResult<()> {
    client.install_workspace_policy(1)?;
    let staged = client.stage_protected_publication(
        (workspace).into(),
        1,
        "streams/opaque",
        ([id; 16]).into(),
        vec![id],
    )?;
    client.adopt_protected_publication(&staged).map(|_| ())
}

#[test]
fn a_rolled_back_store_is_refused_without_host_bookkeeping() {
    let directory = common::directory();
    let root = [92; 32];
    let anchors = Arc::new(MemoryAnchors::default());
    let storage = || StorageConfig::sqlite(directory.path(), root).with_anchors(anchors.clone());
    let client = open(storage());
    let created = client.create_workspace("Owner", None).unwrap();
    let path = SqliteProvider::new(directory.path(), root).path((created.workspace).to_bytes());
    let old = directory.path().join("old-copy");
    client.close().unwrap();
    std::fs::copy(&path, &old).unwrap();

    let client = open(storage());
    client.restore_workspace(created.workspace, None).unwrap();
    publish(&client, (created.workspace).to_bytes(), 1).unwrap();
    client.close().unwrap();
    let latest = directory.path().join("latest-copy");
    std::fs::copy(&path, &latest).unwrap();

    // Whole-file rollback: the anchor in monotonic storage refuses it.
    std::fs::copy(&old, &path).unwrap();
    let client = open(storage());
    let error = client
        .restore_workspace(created.workspace, None)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CandidateStale, "{error:?}");
    assert!(error.message().contains("freshness"), "{error:?}");
    client.close().unwrap();

    std::fs::copy(&latest, &path).unwrap();
    let client = open(storage());
    assert!(matches!(
        client.restore_workspace(created.workspace, None).unwrap(),
        RestoredWorkspace::Active(_)
    ));
    client.close().unwrap();
    directory.close().unwrap();
}

#[test]
fn a_missing_anchor_fails_closed() {
    let directory = common::directory();
    let root = [93; 32];
    let client = open(
        StorageConfig::sqlite(directory.path(), root)
            .with_anchors(Arc::new(MemoryAnchors::default())),
    );
    let created = client.create_workspace("Owner", None).unwrap();
    client.close().unwrap();
    // Another device's anchor storage, or a wiped one.
    let client = open(
        StorageConfig::sqlite(directory.path(), root)
            .with_anchors(Arc::new(MemoryAnchors::default())),
    );
    let error = client
        .restore_workspace(created.workspace, None)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CandidateStale, "{error:?}");
    client.close().unwrap();
    directory.close().unwrap();
}

#[test]
fn sqlite_restore_requires_a_freshness_anchor() {
    let directory = common::directory();
    let root = [95; 32];
    let storage = || StorageConfig::sqlite(directory.path(), root);
    let client = open(storage());
    let created = client.create_workspace("Owner", None).unwrap();
    let anchor = client.record_freshness().unwrap();
    client.close().unwrap();

    let client = open(storage());
    let error = client
        .restore_workspace(created.workspace, None)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CandidateStale, "{error:?}");
    assert!(error.message().contains("freshness anchor"), "{error:?}");
    assert!(matches!(
        client
            .restore_workspace(created.workspace, Some(anchor))
            .unwrap(),
        RestoredWorkspace::Active(_)
    ));
    let removed = client
        .adopt_removal(&client.stage_solo_leave().unwrap())
        .unwrap();
    client.close().unwrap();

    let client = open(storage());
    assert!(matches!(
        client
            .restore_workspace(created.workspace, Some(removed.freshness))
            .unwrap(),
        RestoredWorkspace::Removed(_)
    ));
    client.close().unwrap();
    directory.close().unwrap();
}

#[test]
fn a_crash_after_commit_before_the_anchor_is_confirmed_still_restores() {
    let directory = common::directory();
    let root = [94; 32];
    let anchors = Arc::new(MemoryAnchors::default());
    let storage = || StorageConfig::sqlite(directory.path(), root).with_anchors(anchors.clone());
    let client = open(storage());
    let created = client.create_workspace("Owner", None).unwrap();
    // The commit lands; confirming its anchor fails, as a crash would.
    anchors.fail_confirmations(true);
    let error = publish(&client, (created.workspace).to_bytes(), 1).unwrap_err();
    assert_eq!(error.code(), ErrorCode::StorageFailed, "{error:?}");
    client.close().unwrap();
    anchors.fail_confirmations(false);
    // The pre-commit anchor slot names the landed commit: restore accepts it.
    let client = open(storage());
    client.restore_workspace(created.workspace, None).unwrap();
    publish(&client, (created.workspace).to_bytes(), 2).unwrap();
    client.close().unwrap();
    directory.close().unwrap();
}
