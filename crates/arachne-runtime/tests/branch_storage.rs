//! H1/H2: branch state is saved with its workspace and restored before the
//! next candidate. A restart must not silently discard the rollback window.
use arachne_runtime::{
    Client, ClientConfig, MemoryProvider, Network, RestoredWorkspace, StorageConfig,
};

fn open(provider: &MemoryProvider) -> std::sync::Arc<Client> {
    Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([171; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(provider)).into()),
    })
    .unwrap()
}

fn snapshot_name(epoch: u64) -> Vec<u8> {
    let mut name = b"runtime/branch/snapshot/".to_vec();
    name.extend(epoch.to_be_bytes());
    name
}

#[test]
fn branch_records_survive_restore_and_the_next_candidate() {
    let provider = MemoryProvider::default();
    let client = open(&provider);
    let created = client.create_workspace("Owner", None).unwrap();
    let workspace = created.workspace;
    let invitation = client.stage_invitation(0).unwrap();
    client.adopt_invitation(&invitation).unwrap();
    let meta = provider
        .value((workspace).to_bytes(), b"runtime/branch/meta")
        .expect("the candidate must save branch metadata");
    let prior = provider
        .value((workspace).to_bytes(), &snapshot_name(created.epoch))
        .expect("the candidate must save its pre-commit snapshot");
    client.close().unwrap();

    let client = open(&provider);
    let RestoredWorkspace::Active(restored) = client.restore_workspace(workspace, None).unwrap()
    else {
        panic!("expected an active workspace")
    };
    assert_eq!(restored.epoch, created.epoch + 1);
    let name = client.stage_workspace_name("Restored").unwrap();
    client.adopt_admission(&name).unwrap();
    assert_eq!(
        provider.value((workspace).to_bytes(), b"runtime/branch/meta"),
        Some(meta)
    );
    assert_eq!(
        provider.value((workspace).to_bytes(), &snapshot_name(created.epoch)),
        Some(prior.clone())
    );

    let invitation = client.stage_invitation(0).unwrap();
    client.adopt_invitation(&invitation).unwrap();
    assert_eq!(
        provider.value((workspace).to_bytes(), &snapshot_name(created.epoch)),
        Some(prior)
    );
    assert!(
        provider
            .value((workspace).to_bytes(), &snapshot_name(restored.epoch))
            .is_some()
    );
    client.close().unwrap();

    let client = open(&provider);
    let RestoredWorkspace::Active(restored) = client.restore_workspace(workspace, None).unwrap()
    else {
        panic!("expected an active workspace")
    };
    assert_eq!(restored.epoch, created.epoch + 2);
    assert_eq!(restored.workspace_name.as_deref(), Some("Restored"));
    client.close().unwrap();
}
