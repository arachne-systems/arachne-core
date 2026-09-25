//! Separate process: the unit lifecycle test deliberately exhausts the global registry.
use arachne_runtime::{MemoryProvider, close, create, describe, execute};
use serde_json::{Value, json};

mod common;

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|error| error.to_string())
}

#[test]
fn removed_membership_restore_shuts_down_runtime_and_rejects_active_fallback() {
    use arachne_security::{ManagementAction, PendingJoin, Workspace};
    let seed = [93; 32];
    let provider = MemoryProvider::default();
    let handle = common::stored(&seed, &provider);
    let info: Value = serde_json::from_str(&describe(handle).unwrap()).unwrap();
    let endpoint: [u8; 32] = serde_json::from_value(info["endpoint_key"].clone()).unwrap();
    let admin = Workspace::create([91; 32], "Admin").unwrap();
    let (registered, invite, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
    let admin = registered.workspace;
    let join =
        PendingJoin::from_invitation(&invite, &checkpoint, endpoint, "Former member").unwrap();
    let admitted = admin
        .prepare_admission(endpoint, join.admission_request().unwrap())
        .unwrap();
    let mut proof = join.join_proof().unwrap();
    proof
        .apply_add(&admitted.authorization, &admitted.commit)
        .unwrap();
    let member = join.prepare_workspace(&proof, &admitted.welcome).unwrap();
    let member_id = member.member().unwrap().id();
    // The active member state is in storage; the removal goes through the
    // runtime's own stage and adopt, which saves the removal record.
    arachne_runtime::harness::seed_workspace(&provider, &member, None, None).unwrap();
    let request = json!({"op":"restore_workspace", "workspace":member.id()});
    call(handle, request.clone()).unwrap();
    let action = ManagementAction::Remove(member_id);
    let change = admitted.workspace.prepare_management(action).unwrap();
    let step = json!({"commit":change.commit,"management":{"kind":"remove","member":member_id}});
    let staged = call(handle, json!({"op":"stage_admission_update","step":step})).unwrap();
    let adopted = call(
        handle,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )
    .unwrap();
    assert_eq!(adopted["state"], "removed");
    let _ = close(handle);

    // A fresh session reopens the removed record from storage and shuts down.
    let handle = common::stored(&seed, &provider);
    let value = call(handle, request.clone()).unwrap();
    assert_eq!(value["state"], "removed");
    assert_eq!(value["workspace_ready"], false);
    assert_eq!(value["member"]["display_name"], "Former member");
    assert!(value.get("candidate").is_none());
    assert!(describe(handle).is_err());
    for request in [
        json!({"op":"create_workspace","display_name":"Do not resurrect"}),
        json!({"op":"restore_workspace","workspace":member.id()}),
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
        json!({"op":"install_workspace_policy","revision":99}),
        json!({"op":"install_verified_policy","workspace":member.id(),"revision":99,"endpoints":[]}),
        json!({"op":"publish","workspace":member.id(),"revision":99,"topic":"atak/pli","payload":[1]}),
        json!({"op":"poll"}),
    ] {
        assert_eq!(
            execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap_err(),
            "node is closed"
        );
    }
    close(handle).unwrap();
    assert!(close(handle).is_err());
    // A fresh process/session must reopen the same removed record, never invent
    // an active group. Deliberately restoring a separate old backup is out of scope.
    let restarted = create(Some(&seed)).unwrap();
    common::attach(restarted, &provider);
    assert_eq!(call(restarted, request).unwrap()["state"], "removed");
    close(restarted).unwrap();
}
