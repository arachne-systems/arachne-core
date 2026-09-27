//! A5 item 4: the storage root is the host's, not the endpoint secret's.
use arachne_runtime::{
    Client, ClientConfig, ErrorCode, MemoryProvider, Network, RestoredWorkspace, StorageConfig,
};

mod common;

fn open(secret: Option<[u8; 32]>, storage: StorageConfig) -> std::sync::Arc<Client> {
    Client::open(ClientConfig {
        network: Network::Direct,
        secret: secret.map(|key| key.to_vec()),
        transport: Default::default(),
        storage: Some((storage).into()),
    })
    .unwrap()
}

#[test]
fn a_direct_client_without_an_endpoint_secret_persists() {
    let provider = MemoryProvider::default();
    let client = open(None, StorageConfig::memory(&provider));
    let created = client.create_workspace("Ephemeral", None).unwrap();
    assert!(created.durable);
    client.install_workspace_policy(1).unwrap();
    let staged = client
        .stage_protected_publication(
            created.workspace,
            1,
            "streams/opaque",
            ([1; 16]).into(),
            vec![1],
        )
        .unwrap();
    client.adopt_protected_publication(&staged).unwrap();
    let leave = client.stage_solo_leave().unwrap();
    client.adopt_removal(&leave).unwrap();
}

#[test]
fn a_new_endpoint_identity_keeps_the_store_readable() {
    let directory = common::directory();
    let storage = || StorageConfig::sqlite(directory.path(), [71; 32]);
    let client = open(Some([72; 32]), storage());
    let created = client.create_workspace("Owner", None).unwrap();
    let anchor = client.record_freshness().unwrap();
    client.close().unwrap();

    // The endpoint identity changes; the storage root does not.
    let rotated = open(Some([73; 32]), storage());
    let error = rotated
        .restore_workspace(created.workspace, Some(anchor))
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::WrongState, "{error:?}");
    assert!(error.message().contains("endpoint"), "{error:?}");
    rotated.close().unwrap();

    // Nothing was lost: the original identity still restores it.
    let client = open(Some([72; 32]), storage());
    assert!(matches!(
        client
            .restore_workspace(created.workspace, Some(anchor))
            .unwrap(),
        RestoredWorkspace::Active(_)
    ));
    client.close().unwrap();
    directory.close().unwrap();
}
