//! Separate process: the unit lifecycle test deliberately exhausts the global registry.
use arachne_runtime::{close, create, describe, execute, execute_stored};
use serde_json::{Value, json};

#[test]
fn removed_membership_restore_shuts_down_runtime_and_rejects_active_fallback() {
    use arachne_security::{
        ManagementAction, PendingJoin, PreparedManagementUpdate, StorageKey, Workspace,
    };
    let seed = [93; 32];
    let handle = create(Some(&seed)).unwrap();
    let info: Value = serde_json::from_str(&describe(handle).unwrap()).unwrap();
    let endpoint: [u8; 32] = serde_json::from_value(info["endpoint_key"].clone()).unwrap();
    let admin = Workspace::create([91; 32], "Admin").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
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
    let key = StorageKey::derive(&seed).unwrap();
    let old = member.seal(&key).unwrap();
    let action = ManagementAction::Remove(member.member().unwrap().id());
    let change = admitted.workspace.prepare_management(action).unwrap();
    let PreparedManagementUpdate::Removed(removed) = member
        .prepare_management_update(action, &change.commit)
        .unwrap()
    else {
        panic!("removed member returned active state")
    };
    let sealed = removed.seal(&key).unwrap();
    let request = json!({"op":"restore_workspace", "workspace":member.id()});
    let [metadata, response_snapshot] =
        execute_stored(handle, &serde_json::to_vec(&request).unwrap(), &sealed).unwrap();
    let value: Value = serde_json::from_slice(&metadata).unwrap();
    assert_eq!(value["state"], "removed");
    assert_eq!(value["workspace_ready"], false);
    assert_eq!(value["member"]["display_name"], "Former member");
    assert!(response_snapshot.is_empty());
    assert!(describe(handle).is_err());
    for request in [
        json!({"op":"create_workspace","display_name":"Do not resurrect"}),
        json!({"op":"restore_workspace","workspace":member.id(),"snapshot":old}),
        json!({"op":"issue_invitation"}),
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
    let [metadata, _] =
        execute_stored(restarted, &serde_json::to_vec(&request).unwrap(), &sealed).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&metadata).unwrap()["state"],
        "removed"
    );
    close(restarted).unwrap();
}
