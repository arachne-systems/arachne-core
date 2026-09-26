//! The gossip tag key is one members-only secret, carried to joiners and
//! kept across a runtime save and restore.
use arachne_runtime::{MemoryProvider, close, execute, harness::gossip_tag_key};
use serde_json::{Value, json};

mod common;

fn call(handle: i64, request: Value) -> Value {
    let reply = execute(handle, &serde_json::to_vec(&request).unwrap())
        .unwrap_or_else(|error| panic!("{request}: {error}"));
    serde_json::from_slice(&reply).unwrap()
}

#[test]
fn joiner_shares_the_key_and_keeps_it_across_restore() {
    let admin_provider = MemoryProvider::default();
    let joiner_provider = MemoryProvider::default();
    let admin = common::stored(&[71; 32], &admin_provider);
    let joiner = common::stored(&[72; 32], &joiner_provider);
    let workspace = call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator"}),
    );
    let key = gossip_tag_key(admin).unwrap();
    assert_ne!(json!(key), workspace["workspace"]);
    let staged = call(
        admin,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    );
    let invite = call(
        admin,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )["issued_invitation"]
        .clone();
    let pending = call(
        joiner,
        json!({"op":"begin_join","invitation":invite["invitation"],
        "checkpoint":invite["checkpoint"],"display_name":"Member"}),
    );
    let staged = call(
        admin,
        json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],
        "request":pending["admission_request"]}),
    );
    call(
        admin,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    );
    let reply = call(
        admin,
        json!({"op":"retained_admission","authenticated_endpoint":pending["endpoint"],
        "request":pending["admission_request"]}),
    );
    // Only the encrypted Welcome carries the key.
    for public in [&invite["checkpoint"], &reply["commit"]] {
        let bytes: Vec<u8> = serde_json::from_value(public.clone()).unwrap();
        assert!(!bytes.windows(32).any(|window| window == key));
    }
    let staged = call(
        joiner,
        json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}),
    );
    call(
        joiner,
        json!({"op":"adopt_join","candidate":staged["candidate"]}),
    );
    assert_eq!(gossip_tag_key(joiner).unwrap(), key);
    assert_eq!(gossip_tag_key(admin).unwrap(), key);

    close(joiner).unwrap();
    let joiner = common::stored(&[72; 32], &joiner_provider);
    call(
        joiner,
        json!({"op":"restore_workspace","workspace":workspace["workspace"]}),
    );
    assert_eq!(gossip_tag_key(joiner).unwrap(), key);
    call(
        joiner,
        json!({"op":"install_workspace_policy","revision":3}),
    );
    close(admin).unwrap();
    close(joiner).unwrap();
}
