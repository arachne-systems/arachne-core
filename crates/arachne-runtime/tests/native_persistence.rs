//! One real runtime owner; admission requests/Welcome validation are local.
//! This proves storage lifecycle, not a hundred-endpoint network topology.
use arachne_runtime::{
    close, create, enable_record_storage, execute, restore_record_storage, save_candidate,
};
use arachne_security::{AdmissionAuthorization, Invitation, PendingJoin};
use serde_json::{Value, json};

mod common;
fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|e| e.to_string())
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::from_value(value.clone()).unwrap()
}
fn save(handle: i64, staged: &Value, op: &str) -> Value {
    let token = bytes(&staged["snapshot"]);
    assert_eq!(token.len(), 37);
    assert!(token.starts_with(b"DFRC\x01"));
    assert!(
        call(handle, json!({"op":op,"snapshot":token}))
            .unwrap_err()
            .contains("not been committed")
    );
    let mut wrong = token.clone();
    wrong[36] ^= 1;
    assert!(save_candidate(handle, &wrong).is_err());
    save_candidate(handle, &token).unwrap();
    save_candidate(handle, &token).unwrap();
    call(handle, json!({"op":op,"snapshot":token})).unwrap()
}
#[test]
#[cfg(unix)]
fn runtime_test_directories_are_private_unique_and_cleaned_on_drop() {
    use std::os::unix::fs::PermissionsExt;
    let directory = common::directory();
    let other = common::directory();
    let path = directory.path().to_path_buf();
    assert_ne!(path, other.path());
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    std::fs::write(path.join("private-fixture"), b"test only").unwrap();
    drop(directory);
    assert!(!path.exists());
    assert!(other.path().is_dir());
    other.close().unwrap();
}

#[test]
fn hundred_member_runtime_commits_tokens_and_reopens_without_legacy_snapshots() {
    let directory = common::directory();
    let path = directory.path().join("workspace.db");
    let root = [91; 32];
    let mut handle = create(Some(&root)).unwrap();
    let created = call(
        handle,
        json!({"op":"create_workspace","display_name":"Coordinator"}),
    )
    .unwrap();
    let workspace: [u8; 32] = serde_json::from_value(created["workspace"].clone()).unwrap();
    let legacy = call(handle, json!({"op":"seal_workspace"})).unwrap();
    enable_record_storage(handle, &path, &root).unwrap();
    let mut final_reader = None;
    for member in 1..100u8 {
        let invite = call(handle, json!({"op":"issue_invitation"})).unwrap();
        let invitation = Invitation::from_bytes(&bytes(&invite["invitation"])).unwrap();
        let pending = PendingJoin::from_invitation(
            &invitation,
            &bytes(&invite["checkpoint"]),
            [member; 32],
            "Member",
        )
        .unwrap();
        let request = pending.admission_request().unwrap();
        let staged = call(
            handle,
            json!({"op":"stage_admission","authenticated_endpoint":vec![member;32],"request":request}),
        )
        .unwrap();
        save(handle, &staged, "adopt_admission");
        let reply = call(handle,json!({"op":"retained_admission","authenticated_endpoint":vec![member;32],"request":request})).unwrap();
        let auth = &reply["authorization"];
        let authorization = AdmissionAuthorization {
            invitation_key: bytes(&auth["invitation_key"]).try_into().unwrap(),
            grant_signature: bytes(&auth["grant_signature"]).try_into().unwrap(),
            redemption_signature: bytes(&auth["redemption_signature"]).try_into().unwrap(),
        };
        let mut proof = pending.join_proof().unwrap();
        proof
            .apply_add(&authorization, &bytes(&reply["commit"]))
            .unwrap();
        final_reader = Some(
            pending
                .prepare_workspace(&proof, &bytes(&reply["welcome"]))
                .unwrap(),
        );
        if [16, 64, 99].contains(&member) {
            close(handle).unwrap();
            handle = create(Some(&root)).unwrap();
            let restored = restore_record_storage(handle, &path, &root, workspace).unwrap();
            assert_eq!(restored["members"], u64::from(member) + 1);
            println!("runtime reopened members={}", member + 1);
        }
    }
    let enabled = call(handle, json!({"op":"enable_object_delivery"})).unwrap();
    save(handle, &enabled, "adopt_reception");
    call(
        handle,
        json!({"op":"install_workspace_policy","revision":100}),
    )
    .unwrap();
    let staged=call(handle,json!({"op":"stage_network_publication","revision":100,"topic":"streams/opaque","id":vec![1;16],"payload":[9,8,7]})).unwrap();
    let token = bytes(&staged["snapshot"]);
    assert!(call(handle, json!({"op":"adopt_publication","snapshot":token})).is_err());
    save_candidate(handle, &token).unwrap();
    // Crash after save, before adoption: counter and retained data must survive.
    close(handle).unwrap();
    handle = create(Some(&root)).unwrap();
    restore_record_storage(handle, &path, &root, workspace).unwrap();
    assert!(call(handle, json!({"op":"adopt_publication","snapshot":token})).is_err());
    call(
        handle,
        json!({"op":"install_workspace_policy","revision":100}),
    )
    .unwrap();
    let staged=call(handle,json!({"op":"stage_network_publication","revision":100,"topic":"streams/opaque","id":vec![2;16],"payload":[6]})).unwrap();
    let adopted = save(handle, &staged, "adopt_publication");
    assert_eq!(adopted["sequence"], 2);
    close(handle).unwrap();
    // The encrypted native state preserves the sender counter too.
    let store = arachne_store::Store::open(&path, &root, workspace).unwrap();
    let records = store
        .keys(b"security/")
        .map(|name| (name.to_vec(), store.get(name).unwrap().unwrap()))
        .collect();
    handle = create(Some(&root)).unwrap();
    let description: Value =
        serde_json::from_str(&arachne_runtime::describe(handle).unwrap()).unwrap();
    let endpoint = serde_json::from_value(description["endpoint_key"].clone()).unwrap();
    let mut owner =
        arachne_security::Workspace::restore_records(endpoint, workspace, &records).unwrap();
    let object = owner
        .protect_object(b"counter check", b"test only")
        .unwrap();
    assert_eq!(
        final_reader
            .unwrap()
            .unprotect_object(b"counter check", &object)
            .unwrap()
            .counter,
        3
    );
    drop(store);
    // A stale legacy snapshot cannot overwrite an initialized native database.
    call(
        handle,
        json!({"op":"restore_workspace","workspace":workspace,"snapshot":legacy["snapshot"]}),
    )
    .unwrap();
    assert!(
        enable_record_storage(handle, &path, &root)
            .unwrap_err()
            .contains("already initialized")
    );
    close(handle).unwrap();
    handle = create(Some(&root)).unwrap();
    assert_eq!(
        restore_record_storage(handle, &path, &root, workspace).unwrap()["members"],
        100
    );
    close(handle).unwrap();
    directory.close().unwrap();
}

#[test]
fn migration_preserves_pending_inbox_and_removal_cannot_reopen_active_state() {
    use arachne_delivery::{
        PublisherLog,
        inbox::{InboxStage, ObjectInbox},
    };
    use arachne_security::{ManagementAction, StorageKey, Workspace};
    let root = [103; 32];
    let directory = common::directory();
    let path = directory.path().join("workspace.db");
    let mut handle = create(Some(&root)).unwrap();
    let description: Value =
        serde_json::from_str(&arachne_runtime::describe(handle).unwrap()).unwrap();
    let endpoint = serde_json::from_value(description["endpoint_key"].clone()).unwrap();
    let admin = Workspace::create([104; 32], "Administrator").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let pending = PendingJoin::from_invitation(&invite, &checkpoint, endpoint, "Receiver").unwrap();
    let prepared = admin
        .prepare_admission(endpoint, pending.admission_request().unwrap())
        .unwrap();
    let mut proof = pending.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let reader = pending
        .prepare_workspace(&proof, &prepared.welcome)
        .unwrap();
    let mut admin = prepared.workspace;
    let workspace = reader.id();
    let context = arachne_routing::PublicationContext {
        workspace,
        revision: 2,
        topic: arachne_routing::Topic::new("chat/messages").unwrap(),
        id: [1; 16],
        sequence: std::num::NonZeroU64::new(1),
    };
    let object = admin
        .protect_object(&context.authenticated_bytes(), b"pending chat")
        .unwrap();
    let InboxStage::Prepared(inbox) = ObjectInbox::new(workspace, reader.epoch())
        .stage(&reader, &context, &object)
        .unwrap()
    else {
        panic!("missing candidate")
    };
    let publisher = PublisherLog::new(workspace, reader.member().unwrap().id(), reader.epoch());
    let key = StorageKey::derive(&root).unwrap();
    let legacy = inbox.seal(&reader, &key, &publisher).unwrap();
    call(
        handle,
        json!({"op":"restore_workspace","workspace":workspace,"snapshot":legacy}),
    )
    .unwrap();
    enable_record_storage(handle, &path, &root).unwrap();
    close(handle).unwrap();
    handle = create(Some(&root)).unwrap();
    restore_record_storage(handle, &path, &root, workspace).unwrap();
    let pending = call(handle, json!({"op":"poll_pending_object"})).unwrap();
    assert_eq!(bytes(&pending["payload"]), b"pending chat");
    let removed = admin
        .prepare_management(ManagementAction::Remove(reader.member().unwrap().id()))
        .unwrap();
    let step = json!({"commit":removed.commit,"management":{"kind":"remove","member":reader.member().unwrap().id()}});
    assert!(
        call(handle, json!({"op":"stage_admission_update","step":step}))
            .unwrap_err()
            .contains("pending application")
    );
    let ack=call(handle,json!({"op":"stage_object_acknowledgement","member":pending["member"],"topic":pending["topic"],"counter":pending["counter"],"id":pending["id"]})).unwrap();
    save(handle, &ack, "adopt_reception");
    close(handle).unwrap();
    handle = create(Some(&root)).unwrap();
    restore_record_storage(handle, &path, &root, workspace).unwrap();
    assert_eq!(
        call(handle, json!({"op":"poll_pending_object"})).unwrap(),
        Value::Null
    );
    let removal = call(handle, json!({"op":"stage_admission_update","step":step})).unwrap();
    let token = bytes(&removal["snapshot"]);
    assert!(
        call(handle, json!({"op":"adopt_admission","snapshot":token}))
            .unwrap_err()
            .contains("not been committed")
    );
    save_candidate(handle, &token).unwrap();
    // Removal must survive a crash before adoption and delete every active record.
    close(handle).unwrap();
    handle = create(Some(&root)).unwrap();
    assert_eq!(
        restore_record_storage(handle, &path, &root, workspace).unwrap()["state"],
        "removed"
    );
    assert!(
        call(
            handle,
            json!({"op":"restore_workspace","workspace":workspace,"snapshot":legacy})
        )
        .is_err()
    );
    close(handle).unwrap();
    let store = arachne_store::Store::open(&path, &root, workspace).unwrap();
    assert_eq!(store.keys(b"").count(), 2);
    assert_eq!(store.keys(b"security/").count(), 0);
    assert_eq!(store.keys(b"delivery/").count(), 0);
    drop(store);
    directory.close().unwrap();
}

#[test]
fn native_pending_join_keeps_identity_until_atomic_admission_commit() {
    use arachne_security::Workspace;
    let root = [141; 32];
    let directory = common::directory();
    let path = directory.path().join("workspace.db");
    let admin = Workspace::create([142; 32], "Administrator").unwrap();
    let workspace = admin.id();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let mut handle = create(Some(&root)).unwrap();
    let pending = call(
        handle,
        json!({"op":"begin_join","invitation":invite.export_secret_token().as_slice(),
        "checkpoint":checkpoint,"display_name":"Joining member"}),
    )
    .unwrap();
    enable_record_storage(handle, &path, &root).unwrap();
    close(handle).unwrap();
    handle = create(Some(&root)).unwrap();
    let restored = restore_record_storage(handle, &path, &root, workspace).unwrap();
    assert_eq!(restored["admission_request"], pending["admission_request"]);
    assert_eq!(restored["member"], pending["member"]);
    let endpoint = serde_json::from_value(pending["endpoint"].clone()).unwrap();
    let prepared = admin
        .prepare_admission(endpoint, &bytes(&pending["admission_request"]))
        .unwrap();
    let auth = prepared.authorization;
    let request = json!({"op":"stage_join","welcome":prepared.welcome,"commits":[{"commit":prepared.commit,
        "authorization":{"invitation_key":auth.invitation_key,"grant_signature":auth.grant_signature.as_slice(),
            "redemption_signature":auth.redemption_signature.as_slice()}}]});
    let welcome = bytes(&request["welcome"]);
    let mut metadata = request.clone();
    metadata.as_object_mut().unwrap().remove("welcome");
    let encoded = serde_json::to_vec(&metadata).unwrap();
    assert!(
        arachne_runtime::execute_stored(handle, &serde_json::to_vec(&request).unwrap(), &welcome)
            .is_err()
    );
    assert!(
        arachne_runtime::execute_stored(
            handle,
            &encoded,
            &vec![0; arachne_security::MAX_WELCOME + 1]
        )
        .is_err()
    );
    let [response, token] = arachne_runtime::execute_stored(handle, &encoded, &welcome).unwrap();
    let mut abandoned: Value = serde_json::from_slice(&response).unwrap();
    abandoned["snapshot"] = json!(token);
    assert_eq!(bytes(&abandoned["snapshot"]).len(), 37);
    close(handle).unwrap();
    handle = create(Some(&root)).unwrap();
    assert_eq!(
        restore_record_storage(handle, &path, &root, workspace).unwrap()["admission_request"],
        pending["admission_request"]
    );
    let staged = call(handle, request).unwrap();
    let token = bytes(&staged["snapshot"]);
    assert!(save_candidate(handle, &bytes(&abandoned["snapshot"])).is_err());
    save_candidate(handle, &token).unwrap();
    close(handle).unwrap();
    handle = create(Some(&root)).unwrap();
    let joined = restore_record_storage(handle, &path, &root, workspace).unwrap();
    assert_eq!(joined["members"], 2);
    assert_eq!(joined["member"], pending["member"]);
    close(handle).unwrap();
    let store = arachne_store::Store::open(&path, &root, workspace).unwrap();
    assert!(store.get(b"runtime/pending").unwrap().is_none());
    assert!(store.keys(b"security/").count() > 0);
    drop(store);
    directory.close().unwrap();
}
