//! A5: native record storage is the one persistence mode. Core saves each
//! candidate, reads it back, and only then adopts it.
use arachne_runtime::{
    Client, ClientConfig, ErrorCode, MemoryProvider, Network, RestoredWorkspace, StorageConfig,
};
use serde_json::json;

fn open(secret: u8, storage: Option<&MemoryProvider>) -> Client {
    Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([secret; 32]),
        transport: Default::default(),
        storage: storage.map(StorageConfig::memory),
    })
    .unwrap()
}

fn publish(client: &Client, workspace: [u8; 32], id: u8) -> arachne_runtime::ClientResult<()> {
    client.install_workspace_policy(1)?;
    let staged =
        client.stage_protected_publication(workspace, 1, "streams/opaque", [id; 16], vec![id])?;
    client.adopt_protected_publication(&staged.candidate).map(|_| ())
}

#[test]
fn adopt_saves_and_reads_back_without_a_host_save() {
    let provider = MemoryProvider::default();
    let mut client = open(41, Some(&provider));
    let created = client.create_workspace("Owner", None).unwrap();
    assert!(created.durable);
    publish(&client, created.workspace, 1).unwrap();
    client.close().unwrap();

    let mut client = open(41, Some(&provider));
    let RestoredWorkspace::Active(info) = client.restore_workspace(created.workspace, None).unwrap()
    else {
        panic!("expected an active workspace")
    };
    assert_eq!(info.epoch, created.epoch);
    assert!(info.durable);
    // The sender counter came back from storage: the next sequence is 2.
    client.install_workspace_policy(1).unwrap();
    let staged = client
        .stage_protected_publication(created.workspace, 1, "streams/opaque", [2; 16], vec![2])
        .unwrap();
    client.adopt_protected_publication(&staged.candidate).unwrap();
    client.close().unwrap();
}

#[test]
fn a_read_back_mismatch_stops_the_session_until_restore() {
    let provider = MemoryProvider::default();
    let mut client = open(42, Some(&provider));
    let created = client.create_workspace("Owner", None).unwrap();
    client.install_workspace_policy(1).unwrap();
    let staged = client
        .stage_protected_publication(created.workspace, 1, "streams/opaque", [1; 16], vec![1])
        .unwrap();
    provider.corrupt_reads(true);
    let error = client.adopt_protected_publication(&staged.candidate).unwrap_err();
    assert_eq!(error.code(), ErrorCode::StorageFailed, "{error:?}");
    provider.corrupt_reads(false);
    // Live state did not move, and it cannot move now: the outcome is unknown.
    let error = client.adopt_protected_publication(&staged.candidate).unwrap_err();
    assert_eq!(error.code(), ErrorCode::StorageFailed);
    assert_eq!(
        client.discard_workspace_candidate().unwrap_err().code(),
        ErrorCode::StorageFailed
    );
    client.close().unwrap();
    let mut client = open(42, Some(&provider));
    assert!(matches!(
        client.restore_workspace(created.workspace, None).unwrap(),
        RestoredWorkspace::Active(_)
    ));
    client.close().unwrap();
}

#[test]
fn a_failed_commit_stops_the_session_until_restore() {
    let provider = MemoryProvider::default();
    let mut client = open(43, Some(&provider));
    let created = client.create_workspace("Owner", None).unwrap();
    client.install_workspace_policy(1).unwrap();
    let staged = client
        .stage_protected_publication(created.workspace, 1, "streams/opaque", [1; 16], vec![1])
        .unwrap();
    provider.fail_next_commit();
    let error = client.adopt_protected_publication(&staged.candidate).unwrap_err();
    assert_eq!(error.code(), ErrorCode::StorageFailed);
    assert_eq!(
        client.install_workspace_policy(1).unwrap_err().code(),
        ErrorCode::StorageFailed
    );
    client.close().unwrap();
    let mut client = open(43, Some(&provider));
    client.restore_workspace(created.workspace, None).unwrap();
    publish(&client, created.workspace, 3).unwrap();
    client.close().unwrap();
}

#[test]
fn an_uncertain_save_blocks_discard() {
    let provider = MemoryProvider::default();
    let handle = arachne_runtime::create(Some(&[44; 32])).unwrap();
    arachne_runtime::attach_storage(handle, StorageConfig::memory(&provider)).unwrap();
    let call = |request: serde_json::Value| {
        arachne_runtime::execute(handle, &serde_json::to_vec(&request).unwrap())
            .map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).unwrap())
    };
    call(json!({"op":"create_workspace","display_name":"Owner"})).unwrap();
    let staged = call(json!({"op":"stage_workspace_name","workspace_name":"Named"})).unwrap();
    assert!(staged.get("snapshot").is_none());
    // A drive op saves before it adopts; a crash between the two leaves the
    // candidate in storage. Simulate the save alone with a failed adoption.
    provider.fail_next_commit();
    assert!(call(json!({"op":"adopt_admission","candidate":staged["candidate"]})).is_err());
    let discard = call(json!({"op":"discard_workspace_candidate"})).unwrap_err();
    assert!(discard.contains("uncertain"), "{discard}");
    arachne_runtime::close(handle).unwrap();
}

#[test]
fn host_snapshot_paths_are_gone() {
    let provider = MemoryProvider::default();
    let handle = arachne_runtime::create(Some(&[45; 32])).unwrap();
    arachne_runtime::attach_storage(handle, StorageConfig::memory(&provider)).unwrap();
    let call = |request: serde_json::Value| {
        arachne_runtime::execute(handle, &serde_json::to_vec(&request).unwrap())
    };
    let created = call(json!({"op":"create_workspace","display_name":"Owner"})).unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created).unwrap();
    assert_eq!(created["durable"], true);
    for op in ["seal_workspace", "seal_pending_join"] {
        assert!(call(json!({ "op": op })).is_err(), "{op}");
    }
    assert!(
        call(json!({"op":"restore_workspace","workspace":created["workspace"],"snapshot":[1]}))
            .is_err()
    );
    let staged = call(json!({"op":"stage_workspace_name","workspace_name":"Named"})).unwrap();
    let staged: serde_json::Value = serde_json::from_slice(&staged).unwrap();
    assert!(
        call(json!({"op":"adopt_admission","snapshot":staged["candidate"]})).is_err(),
        "the adopt ops take `candidate`"
    );
    call(json!({"op":"adopt_admission","candidate":staged["candidate"]})).unwrap();
    arachne_runtime::close(handle).unwrap();
}

#[test]
fn without_storage_a_session_cannot_hold_a_workspace() {
    let mut client = open(46, None);
    let error = client.create_workspace("Owner", None).unwrap_err();
    assert_eq!(error.code(), ErrorCode::WrongState, "{error:?}");
    assert!(error.message().contains("storage"));
    client.close().unwrap();
}

#[test]
fn create_workspace_is_durable_before_any_adoption() {
    let provider = MemoryProvider::default();
    let mut client = open(47, Some(&provider));
    let created = client.create_workspace("Owner", Some("Team")).unwrap();
    assert!(created.durable);
    assert!(client.workspace_state().unwrap().durable);
    client.close().unwrap();
    let mut client = open(47, Some(&provider));
    let RestoredWorkspace::Active(info) = client.restore_workspace(created.workspace, None).unwrap()
    else {
        panic!("expected an active workspace")
    };
    assert_eq!(info.workspace_name.as_deref(), Some("Team"));
    assert_eq!(info.member_count, 1);
    client.close().unwrap();
}
