use arachne_runtime::{
    close, create, describe, enable_record_storage, execute, restore_record_storage, save_candidate,
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

mod common;

fn call(h: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(h, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|e| e.to_string())
}
fn info(h: i64) -> Value {
    serde_json::from_str(&describe(h).unwrap()).unwrap()
}
fn route(from: i64, to: i64) {
    let node = info(to);
    call(
        from,
        json!({"op":"add_address_hint","peer":node["endpoint_key"],
        "address":node["bound_address"].as_str().unwrap().replace("0.0.0.0:", "127.0.0.1:")}),
    )
    .unwrap();
}
fn incoming(h: i64) -> Value {
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        let value = call(h, json!({"op":"poll_admission"})).unwrap();
        if !value.is_null() {
            return value;
        }
        assert!(Instant::now() < until, "no leave request");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn leave_over_iroh_retries_saved_outcome_then_restores_only_terminal_state() {
    let mut admin = create(Some(&[71; 32])).unwrap();
    let member = create(Some(&[72; 32])).unwrap();
    let created = call(
        admin,
        json!({"op":"create_workspace","display_name":"Admin"}),
    )
    .unwrap();
    let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
    let join = call(
        member,
        json!({"op":"begin_join","display_name":"Departing member",
        "invitation":invite["invitation"],"checkpoint":invite["checkpoint"]}),
    )
    .unwrap();
    let admission = call(admin, json!({"op":"stage_admission","authenticated_endpoint":join["endpoint"],"request":join["admission_request"]})).unwrap();
    call(
        admin,
        json!({"op":"adopt_admission","snapshot":admission["snapshot"]}),
    )
    .unwrap();
    let reply = call(admin, json!({"op":"retained_admission","authenticated_endpoint":join["endpoint"],"request":join["admission_request"]})).unwrap();
    let joined = call(member, json!({"op":"stage_join","welcome":reply["welcome"],"commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]})).unwrap();
    call(
        member,
        json!({"op":"adopt_join","snapshot":joined["snapshot"]}),
    )
    .unwrap();
    let dir = common::directory();
    let a = dir.path().join("admin.db");
    let b = dir.path().join("member.db");
    enable_record_storage(admin, &a, &[71; 32]).unwrap();
    enable_record_storage(member, &b, &[72; 32]).unwrap();
    assert!(call(admin, json!({"op":"stage_solo_leave"})).is_err());
    route(member, admin);
    let peer = info(admin)["endpoint_key"].clone();
    let first =
        std::thread::spawn(move || call(member, json!({"op":"leave_via_peer","peer":peer})));
    let staged = incoming(admin);
    assert_eq!(staged["leaving"], true);
    assert!(call(admin, json!({"op":"send_admission_reply"})).is_err());
    save_candidate(
        admin,
        &serde_json::from_value::<Vec<u8>>(staged["snapshot"].clone()).unwrap(),
    )
    .unwrap();
    let adopted = call(
        admin,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap();
    assert_eq!(adopted["members"], 1);
    close(admin).unwrap(); // Saved departure, lost reply.
    assert!(first.join().unwrap().is_err());
    admin = create(Some(&[71; 32])).unwrap();
    let restored = restore_record_storage(
        admin,
        &a,
        &[71; 32],
        serde_json::from_value(created["workspace"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(restored["members"], 1);
    route(member, admin);
    let peer = info(admin)["endpoint_key"].clone();
    let retry =
        std::thread::spawn(move || call(member, json!({"op":"leave_via_peer","peer":peer})));
    assert_eq!(incoming(admin)["state"], "reply_ready");
    call(admin, json!({"op":"send_admission_reply"})).unwrap();
    let departed = retry.join().unwrap().unwrap();
    assert_eq!(departed["removed"], true);
    assert!(
        call(
            member,
            json!({"op":"adopt_admission","snapshot":departed["snapshot"]})
        )
        .is_err()
    );
    save_candidate(
        member,
        &serde_json::from_value::<Vec<u8>>(departed["snapshot"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        call(
            member,
            json!({"op":"adopt_admission","snapshot":departed["snapshot"]})
        )
        .unwrap()["state"],
        "removed"
    );
    assert!(call(member, json!({"op":"member_roster"})).is_err());
    close(member).unwrap();
    let member = create(Some(&[72; 32])).unwrap();
    assert_eq!(
        restore_record_storage(
            member,
            &b,
            &[72; 32],
            serde_json::from_value(created["workspace"].clone()).unwrap()
        )
        .unwrap()["state"],
        "removed"
    );
    assert!(
        call(
            member,
            json!({"op":"install_workspace_policy","revision":9})
        )
        .is_err()
    );
    close(member).unwrap();
    close(admin).unwrap();
    dir.close().unwrap();
}
