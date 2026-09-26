//! B3c self-update policy over real Iroh nodes with native record storage:
//! a member that just adopted its Welcome self-updates, offers the commit to
//! the administrator, and adopts it only after the administrator did.
use arachne_runtime::{StorageConfig, attach_storage, close, create, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

mod common;

fn call(handle: i64, request: Value) -> Value {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap())
        .unwrap()
}

fn info(handle: i64) -> Value {
    serde_json::from_str(&describe(handle).unwrap()).unwrap()
}

fn address(info: &Value) -> String {
    info["bound_address"].as_str().unwrap().replace("0.0.0.0:", "127.0.0.1:")
}

#[test]
fn a_new_member_self_updates_through_its_administrator() {
    let directory = common::directory();
    let member_directory = common::directory();
    let admin = create(Some(&[121; 32])).unwrap();
    let member = create(Some(&[122; 32])).unwrap();
    attach_storage(admin, StorageConfig::sqlite(directory.path(), [121; 32])).unwrap();
    attach_storage(member, StorageConfig::sqlite(member_directory.path(), [122; 32])).unwrap();
    call(admin, json!({"op":"create_workspace","display_name":"Admin"}));
    let staged = call(admin, json!({"op":"stage_invitation","personal":false,"expires_at":0}));
    let invite = call(admin, json!({"op":"adopt_admission","candidate":staged["candidate"]}))
        ["issued_invitation"]
        .clone();
    let (admin_info, member_info) = (info(admin), info(member));
    let pending = call(
        member,
        json!({"op":"begin_join","display_name":"Member","invitation":invite["invitation"],
            "checkpoint":invite["checkpoint"],"peers":[admin_info["endpoint_key"]]}),
    );
    let workspace = pending["workspace"].clone();
    call(member, json!({"op":"add_address_hint","peer":admin_info["endpoint_key"],
        "address":address(&admin_info)}));
    call(admin, json!({"op":"add_address_hint","peer":member_info["endpoint_key"],
        "address":address(&member_info)}));

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut joined = false;
    let mut updated = None;
    let mut admin_epochs = Vec::new();
    while updated.is_none() {
        assert!(Instant::now() < deadline, "no self-update: joined={joined}");
        let tick = call(admin, json!({"op":"drive_workspace"}));
        if tick["state"] == "workspace_committed" {
            admin_epochs.push(tick["epoch"].clone());
        }
        let step = if joined {
            call(member, json!({"op":"drive_workspace"}))
        } else {
            call(member, json!({"op":"drive_join"}))
        };
        match step["state"].as_str() {
            Some("workspace_joined") => joined = true,
            Some("self_update_committed") => updated = Some(step),
            Some("self_update_refused") => panic!("administrator refused: {step}"),
            _ => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    let updated = updated.unwrap();
    // The administrator adopted the step before the member did.
    assert!(admin_epochs.contains(&updated["epoch"]), "{admin_epochs:?} {updated}");
    assert_eq!(updated["workspace"], workspace);
    let admin_roster = call(admin, json!({"op":"member_roster"}));
    let member_roster = call(member, json!({"op":"member_roster"}));
    assert_eq!(admin_roster["epoch"], member_roster["epoch"]);
    // Once is enough: the leaf now comes from a commit, and 24 h or 10,000
    // objects have not passed.
    for _ in 0..20 {
        let step = call(member, json!({"op":"drive_workspace"}));
        assert!(!step["state"].as_str().unwrap_or("").starts_with("self_update"), "{step}");
        call(admin, json!({"op":"drive_workspace"}));
    }
    close(admin).unwrap();
    close(member).unwrap();
}
