use arachne_runtime::{MemoryProvider, close, describe, execute, wait_for_work};
use serde_json::{Value, json};
use std::time::Instant;

mod common;

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|error| error.to_string())
}

fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect()
}

fn issue(h: i64) -> Value {
    let staged = call(
        h,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    )
    .unwrap();
    call(
        h,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )
    .unwrap()["issued_invitation"]
        .clone()
}

struct Owner {
    handle: i64,
    peer: Value,
    address: String,
    invitation: Value,
    _provider: MemoryProvider,
}

fn owner(seed: u8) -> Owner {
    let provider = MemoryProvider::default();
    let handle = common::stored(&[seed; 32], &provider);
    let _created = call(
        handle,
        json!({"op":"create_workspace","display_name":"Owner","workspace_name":"Compact join"}),
    )
    .unwrap();
    let invitation = issue(handle);
    let info: Value = serde_json::from_str(&describe(handle).unwrap()).unwrap();
    Owner {
        handle,
        peer: info["endpoint_key"].clone(),
        address: info["bound_address"].as_str().unwrap().to_owned(),
        invitation,
        _provider: provider,
    }
}

fn complete_join(handle: i64) -> Value {
    loop {
        let value = call(handle, json!({"op":"drive_join"})).unwrap();
        match value["state"].as_str() {
            Some("workspace_joined") => return value,
            Some("admission_pending") => assert!(wait_for_work(handle).unwrap()),
            Some("admission_waiting") => continue,
            state => panic!("unexpected join state: {state:?}"),
        }
    }
}

#[test]
fn async_driver_persists_selected_peer_and_exact_pending_request() {
    let owner = common::stored(&[231; 32], &MemoryProvider::default());
    let provider = MemoryProvider::default();
    let joiner = common::stored(&[232; 32], &provider);
    let _created = call(
        owner,
        json!({"op":"create_workspace","display_name":"Owner","workspace_name":"Async join"}),
    )
    .unwrap();
    let invitation = issue(owner);
    let owner_info: Value = serde_json::from_str(&describe(owner).unwrap()).unwrap();
    let owner_peer = bytes(&owner_info["endpoint_key"]);
    let pending = call(
        joiner,
        json!({
            "op":"begin_join",
            "display_name":"Pending member",
            "invitation":invitation["invitation"],
            "checkpoint":invitation["checkpoint"],
            "peers":[owner_peer],
        }),
    )
    .unwrap();
    assert!(pending.get("invitation").is_none());
    let workspace: [u8; 32] = bytes(&pending["workspace"]).try_into().unwrap();
    let request = pending["admission_request"].clone();

    let started = Instant::now();
    let first = call(joiner, json!({"op":"drive_join"})).unwrap();
    assert_eq!(first["state"], "admission_pending");
    assert_eq!(first["peer"], json!(owner_peer));
    assert!(
        started.elapsed().as_millis() < 500,
        "driver still blocks on the dial"
    );

    close(joiner).unwrap();
    let restored_handle = common::stored(&[232; 32], &provider);
    let restored = call(
        restored_handle,
        json!({"op":"restore_workspace","workspace":workspace}),
    )
    .unwrap();
    assert_eq!(restored["state"], "pending");
    assert_eq!(restored["admission_request"], request);

    let resumed = call(restored_handle, json!({"op":"drive_join"})).unwrap();
    assert_eq!(resumed["state"], "admission_pending");
    assert_eq!(resumed["peer"], json!(owner_peer));

    let reset = call(restored_handle, json!({"op":"reset_workspace"})).unwrap();
    assert_eq!(reset["state"], "reset");
    assert!(call(restored_handle, json!({"op":"drive_join"})).is_err());

    close(restored_handle).unwrap();
    close(owner).unwrap();
}

#[test]
fn compact_pending_invitation_restores_in_rust_and_joins_without_host_hydration() {
    let owner = owner(233);
    let provider = MemoryProvider::default();
    let joiner = common::stored(&[234; 32], &provider);
    let pending = call(
        joiner,
        json!({
            "op":"begin_join",
            "display_name":"Compact member",
            "invitation":owner.invitation["invitation"].clone(),
            "peers":[owner.peer.clone()],
        }),
    )
    .unwrap();
    assert!(pending.get("invitation").is_none());
    let workspace: [u8; 32] = bytes(&pending["workspace"]).try_into().unwrap();
    assert_eq!(pending["durable"], true);
    close(joiner).unwrap();

    let resumed = common::stored(&[234; 32], &provider);
    let restored = call(
        resumed,
        json!({"op":"restore_workspace","workspace":workspace}),
    )
    .unwrap();
    assert_eq!(restored["state"], "pending");
    assert_eq!(restored["activity"]["state"], "joining");
    assert!(restored.get("invitation").is_none());
    call(
        resumed,
        json!({"op":"add_address_hint","peer":owner.peer.clone(),"address":owner.address}),
    )
    .unwrap();

    let requester = std::thread::spawn(move || complete_join(resumed));
    assert!(wait_for_work(owner.handle).unwrap());
    loop {
        let value = call(owner.handle, json!({"op":"drive_workspace"})).unwrap();
        if value["state"] == "workspace_committed" {
            break;
        }
        assert_eq!(value["state"], "admission_queued");
    }
    let joined = requester.join().unwrap();
    assert_eq!(joined["state"], "workspace_joined");
    close(owner.handle).unwrap();
}
