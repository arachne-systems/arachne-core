use arachne_runtime::{MemoryProvider, close, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

mod common;

fn call(handle: i64, request: Value) -> Value {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap())
        .unwrap()
}

fn issue_invitation(handle: i64) -> Value {
    let staged = call(
        handle,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    );
    call(
        handle,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )["issued_invitation"]
        .clone()
}

fn synchronize(server: i64, client: i64, peer: &Value) -> Value {
    call(client, json!({"op":"fetch_membership_update","peer":peer}));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        call(server, json!({"op":"poll_admission"}));
        let response = call(client, json!({"op":"poll_membership_update"}));
        if !response.is_null() {
            return response;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn unchanged_state_does_not_repeat_profiles_but_restart_recovers_them() {
    let admin_provider = MemoryProvider::default();
    let member_provider = MemoryProvider::default();
    let admin = common::stored(&[151; 32], &admin_provider);
    let member = common::stored(&[152; 32], &member_provider);
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator"}),
    );
    let invite = issue_invitation(admin);
    let begin = call(
        member,
        json!({"op":"begin_join","invitation":invite["invitation"],
        "checkpoint":invite["checkpoint"],"display_name":"Peer"}),
    );
    let staged = call(
        admin,
        json!({"op":"stage_admission",
        "authenticated_endpoint":begin["endpoint"],"request":begin["admission_request"]}),
    );
    call(
        admin,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    );
    let reply = call(
        admin,
        json!({"op":"retained_admission",
        "authenticated_endpoint":begin["endpoint"],"request":begin["admission_request"]}),
    );
    let joined = call(
        member,
        json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}),
    );
    call(
        member,
        json!({"op":"adopt_join","candidate":joined["candidate"]}),
    );
    let info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
    let peer = &info["endpoint_key"];
    let address = info["bound_address"]
        .as_str()
        .unwrap()
        .replace("0.0.0.0:", "127.0.0.1:");
    call(
        member,
        json!({"op":"add_address_hint","peer":peer,"address":address}),
    );
    for _ in 0..3 {
        assert_eq!(
            synchronize(admin, member, peer)["state"],
            "membership_current"
        );
    }
    let before = call(member, json!({"op":"workspace_metrics"}));
    let mut repeated_profiles = 0;
    for _ in 0..20 {
        let response = synchronize(admin, member, peer);
        assert_eq!(response["state"], "membership_current");
        repeated_profiles += usize::from(response.get("profiles").is_some());
    }
    let after = call(member, json!({"op":"workspace_metrics"}));
    eprintln!(
        "20 unchanged membership exchanges: repeated_profiles={repeated_profiles} sent={} received={}",
        after["sent_bytes"].as_u64().unwrap() - before["sent_bytes"].as_u64().unwrap(),
        after["received_bytes"].as_u64().unwrap() - before["received_bytes"].as_u64().unwrap()
    );
    let roster = call(member, json!({"op":"member_roster"}));
    assert!(
        roster["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["display_name"].is_string())
    );
    // The requester still remembers agreement, but the responder has lost its
    // transient profile cache. Comparing the actual set must repair both sides.
    close(admin).unwrap();
    let admin = common::stored(&[151; 32], &admin_provider);
    call(
        admin,
        json!({"op":"restore_workspace","workspace":invite["workspace"]}),
    );
    let restarted_info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
    let address = restarted_info["bound_address"]
        .as_str()
        .unwrap()
        .replace("0.0.0.0:", "127.0.0.1:");
    call(
        member,
        json!({"op":"add_address_hint","peer":peer,"address":address}),
    );
    for _ in 0..3 {
        assert_eq!(
            synchronize(admin, member, peer)["state"],
            "membership_current"
        );
    }
    let restored_server = call(admin, json!({"op":"member_roster"}));
    assert!(
        restored_server["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["display_name"].is_string())
    );
    close(member).unwrap();
    let restarted = common::stored(&[152; 32], &member_provider);
    call(
        restarted,
        json!({"op":"restore_workspace","workspace":invite["workspace"]}),
    );
    call(
        restarted,
        json!({"op":"add_address_hint","peer":peer,"address":address}),
    );
    for _ in 0..3 {
        assert_eq!(
            synchronize(admin, restarted, peer)["state"],
            "membership_current"
        );
    }
    let restored = call(restarted, json!({"op":"member_roster"}));
    assert!(
        restored["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["display_name"].is_string())
    );
    close(admin).unwrap();
    close(restarted).unwrap();
    assert_eq!(
        repeated_profiles, 0,
        "unchanged verified presentation must not be retransmitted"
    );
}
