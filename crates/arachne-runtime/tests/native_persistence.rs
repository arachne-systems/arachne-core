//! One real runtime owner; admission requests/Welcome validation are local.
//! This proves storage lifecycle, not a hundred-endpoint network topology.
use arachne_runtime::{
    FreshnessAnchor, SqliteProvider, StorageConfig, attach_storage, close, create, execute,
    record_freshness,
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
/// A session with SQLite record storage in `directory`.
fn open(root: &[u8; 32], directory: &std::path::Path) -> i64 {
    let handle = create(Some(root)).unwrap();
    attach_storage(handle, StorageConfig::sqlite(directory, *root)).unwrap();
    handle
}
fn restore(handle: i64, workspace: [u8; 32]) -> Result<Value, String> {
    call(handle, json!({"op":"restore_workspace","workspace":workspace}))
}
fn adopt(handle: i64, staged: &Value, op: &str) -> Value {
    let token = bytes(&staged["candidate"]);
    assert_eq!(token.len(), 37);
    assert!(token.starts_with(b"DFRC\x01"));
    let mut wrong = token.clone();
    wrong[36] ^= 1;
    assert!(call(handle, json!({"op":op,"candidate":wrong})).is_err());
    call(handle, json!({"op":op,"candidate":token})).unwrap()
}
#[test]
fn restore_with_freshness_anchor_rejects_a_rolled_back_database() {
    let directory = common::directory();
    let root = [93; 32];
    let mut handle = open(&root, directory.path());
    assert!(record_freshness(handle).is_err());
    let created = call(
        handle,
        json!({"op":"create_workspace","display_name":"Owner"}),
    )
    .unwrap();
    assert_eq!(created["durable"], true);
    let workspace: [u8; 32] = serde_json::from_value(created["workspace"].clone()).unwrap();
    let path = SqliteProvider::new(directory.path(), root).path(workspace);
    let old = directory.path().join("workspace-old.db");
    let enabled = record_freshness(handle).unwrap();
    close(handle).unwrap();
    // The attacker's copy: an authentic, older database.
    std::fs::copy(&path, &old).unwrap();

    handle = open(&root, directory.path());
    call(handle, json!({"op":"restore_workspace","workspace":workspace,
        "freshness":enabled.to_bytes().to_vec()}))
    .unwrap();
    call(handle, json!({"op":"install_workspace_policy","revision":1})).unwrap();
    let staged = call(
        handle,
        json!({"op":"stage_network_publication","workspace":workspace,"revision":1,
            "topic":"streams/opaque","id":vec![1;16],"payload":[1]}),
    )
    .unwrap();
    call(handle, json!({"op":"adopt_publication","candidate":staged["candidate"]})).unwrap();
    let latest = record_freshness(handle).unwrap();
    assert!(latest.revision > enabled.revision);
    assert_eq!(FreshnessAnchor::from_bytes(&latest.to_bytes()).unwrap(), latest);
    close(handle).unwrap();

    // Whole-database rollback: restoring would replay the sender counter.
    std::fs::copy(&old, &path).unwrap();
    handle = open(&root, directory.path());
    let rejected = call(handle, json!({"op":"restore_workspace","workspace":workspace,
        "freshness":latest.to_bytes().to_vec()}))
    .unwrap_err();
    assert!(rejected.contains("freshness"), "{rejected}");
    // Rejection leaves the session empty; the matching anchor still restores.
    assert!(record_freshness(handle).is_err());
    call(handle, json!({"op":"restore_workspace","workspace":workspace,
        "freshness":enabled.to_bytes().to_vec()}))
    .unwrap();
    close(handle).unwrap();
    // Without a monotonic anchor store the anchor stays optional.
    handle = open(&root, directory.path());
    restore(handle, workspace).unwrap();
    close(handle).unwrap();
    directory.close().unwrap();
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
fn hundred_member_runtime_commits_and_reopens() {
    let directory = common::directory();
    let root = [91; 32];
    let mut handle = open(&root, directory.path());
    let created = call(
        handle,
        json!({"op":"create_workspace","display_name":"Coordinator"}),
    )
    .unwrap();
    let workspace: [u8; 32] = serde_json::from_value(created["workspace"].clone()).unwrap();
    let path = SqliteProvider::new(directory.path(), root).path(workspace);
    let mut final_reader = None;
    // Each join also registers its link (one commit); the policy revision is epoch + 1.
    let mut revision = 0;
    for member in 1..100u8 {
        let staged = call(
            handle,
            json!({"op":"stage_invitation","personal":false,"expires_at":0}),
        )
        .unwrap();
        let invite = call(
            handle,
            json!({"op":"adopt_admission","candidate":staged["candidate"]}),
        )
        .unwrap()["issued_invitation"]
            .clone();
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
        adopt(handle, &staged, "adopt_admission");
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
            handle = open(&root, directory.path());
            let restored = restore(handle, workspace).unwrap();
            assert_eq!(restored["members"], u64::from(member) + 1);
            revision = restored["epoch"].as_u64().unwrap() + 1;
            println!("runtime reopened members={}", member + 1);
        }
    }
    call(
        handle,
        json!({"op":"install_workspace_policy","revision":revision}),
    )
    .unwrap();
    // A staged publication that is never adopted is never saved or sent.
    let abandoned=call(handle,json!({"op":"stage_network_publication","revision":revision,"topic":"streams/opaque","id":vec![9;16],"payload":[9]})).unwrap();
    close(handle).unwrap();
    handle = open(&root, directory.path());
    restore(handle, workspace).unwrap();
    assert!(call(handle, json!({"op":"adopt_publication","candidate":abandoned["candidate"]})).is_err());
    call(
        handle,
        json!({"op":"install_workspace_policy","revision":revision}),
    )
    .unwrap();
    let staged=call(handle,json!({"op":"stage_network_publication","revision":revision,"topic":"streams/opaque","id":vec![1;16],"payload":[9,8,7]})).unwrap();
    assert_eq!(adopt(handle, &staged, "adopt_publication")["sequence"], 1);
    // The adopted publication's counter is in storage before it leaves.
    close(handle).unwrap();
    handle = open(&root, directory.path());
    restore(handle, workspace).unwrap();
    call(
        handle,
        json!({"op":"install_workspace_policy","revision":revision}),
    )
    .unwrap();
    let staged=call(handle,json!({"op":"stage_network_publication","revision":revision,"topic":"streams/opaque","id":vec![2;16],"payload":[6]})).unwrap();
    assert_eq!(adopt(handle, &staged, "adopt_publication")["sequence"], 2);
    close(handle).unwrap();
    // The encrypted native state preserves the sender counter too.
    let store = arachne_store::Store::open_existing(&path, &root, workspace).unwrap();
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
        .protect_object(b"counter", b"counter check", b"test only")
        .unwrap();
    assert_eq!(
        final_reader
            .unwrap()
            .unprotect_object(b"counter", b"counter check", &object)
            .unwrap()
            .counter,
        3
    );
    drop(store);
    close(handle).unwrap();
    handle = open(&root, directory.path());
    assert_eq!(restore(handle, workspace).unwrap()["members"], 100);
    close(handle).unwrap();
    directory.close().unwrap();
}

#[test]
fn seeded_pending_inbox_survives_restart_and_removal_cannot_reopen_active_state() {
    use arachne_delivery::{
        PublisherLog,
        inbox::{InboxStage, ObjectInbox},
    };
    use arachne_security::{ManagementAction, Workspace};
    let root = [103; 32];
    let directory = common::directory();
    let provider = SqliteProvider::new(directory.path(), root);
    let mut handle = open(&root, directory.path());
    let description: Value =
        serde_json::from_str(&arachne_runtime::describe(handle).unwrap()).unwrap();
    let endpoint = serde_json::from_value(description["endpoint_key"].clone()).unwrap();
    let admin = Workspace::create([104; 32], "Administrator").unwrap();
    let (registered, invite, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
    let admin = registered.workspace;
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
        .protect_object(
            context.topic.namespace().as_bytes(),
            &context.authenticated_bytes(),
            b"pending chat",
        )
        .unwrap();
    let InboxStage::Prepared(inbox) = ObjectInbox::new(workspace, reader.epoch())
        .stage(&reader, &context, &object)
        .unwrap()
    else {
        panic!("missing candidate")
    };
    let publisher = PublisherLog::new(&reader).unwrap();
    arachne_runtime::harness::seed_workspace(&provider, &reader, Some(&publisher), Some(&inbox))
        .unwrap();
    restore(handle, workspace).unwrap();
    close(handle).unwrap();
    handle = open(&root, directory.path());
    restore(handle, workspace).unwrap();
    let pending = call(handle, json!({"op":"poll_pending_object"})).unwrap();
    assert_eq!(bytes(&pending["payload"]), b"pending chat");
    let removed = admin
        .prepare_management(ManagementAction::Remove(reader.member().unwrap().id()))
        .unwrap();
    let step = json!({"commit":removed.commit,"management":{"kind":"remove","member":reader.member().unwrap().id()}});
    // A pending object never delays a membership step (A3); this test acks
    // first only to check acknowledgement persistence before the removal.
    let ack=call(handle,json!({"op":"stage_object_acknowledgement","member":pending["member"],"topic":pending["topic"],"counter":pending["counter"],"id":pending["id"]})).unwrap();
    adopt(handle, &ack, "adopt_reception");
    close(handle).unwrap();
    handle = open(&root, directory.path());
    restore(handle, workspace).unwrap();
    assert_eq!(
        call(handle, json!({"op":"poll_pending_object"})).unwrap(),
        Value::Null
    );
    let removal = call(handle, json!({"op":"stage_admission_update","step":step})).unwrap();
    // Adoption saves the removal first and deletes every active record.
    assert_eq!(adopt(handle, &removal, "adopt_admission")["state"], "removed");
    assert!(call(handle, json!({"op":"workspace_state"})).is_err());
    handle = open(&root, directory.path());
    assert_eq!(restore(handle, workspace).unwrap()["state"], "removed");
    handle = open(&root, directory.path());
    // A new join may reuse the store; a new workspace cannot resurrect it.
    let store = arachne_store::Store::open_existing(&provider.path(workspace), &root, workspace)
        .unwrap();
    assert_eq!(store.keys(b"").count(), 3); // token, endpoint, removal
    assert_eq!(store.keys(b"security/").count(), 0);
    assert_eq!(store.keys(b"delivery/").count(), 0);
    drop(store);
    close(handle).unwrap();
    directory.close().unwrap();
}

#[test]
fn native_pending_join_keeps_identity_until_atomic_admission_commit() {
    use arachne_security::Workspace;
    let root = [141; 32];
    let directory = common::directory();
    let admin = Workspace::create([142; 32], "Administrator").unwrap();
    let workspace = admin.id();
    let (registered, invite, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
    let admin = registered.workspace;
    let mut handle = open(&root, directory.path());
    let pending = call(
        handle,
        json!({"op":"begin_join","invitation":invite.export_secret_token().as_slice(),
        "checkpoint":checkpoint,"display_name":"Joining member"}),
    )
    .unwrap();
    assert_eq!(pending["durable"], true);
    close(handle).unwrap();
    handle = open(&root, directory.path());
    let restored = restore(handle, workspace).unwrap();
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
    assert!(
        arachne_runtime::execute_stored(handle, br#"{"op":"endpoint_info"}"#, &welcome).is_err()
    );
    let response = arachne_runtime::execute_stored(handle, &encoded, &welcome).unwrap();
    let abandoned: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(bytes(&abandoned["candidate"]).len(), 37);
    // A crash before adoption: storage still holds the pending join.
    close(handle).unwrap();
    handle = open(&root, directory.path());
    assert_eq!(
        restore(handle, workspace).unwrap()["admission_request"],
        pending["admission_request"]
    );
    let staged = call(handle, request).unwrap();
    assert!(call(handle, json!({"op":"adopt_join","candidate":abandoned["candidate"]})).is_err());
    adopt(handle, &staged, "adopt_join");
    close(handle).unwrap();
    handle = open(&root, directory.path());
    let joined = restore(handle, workspace).unwrap();
    assert_eq!(joined["members"], 2);
    assert_eq!(joined["member"], pending["member"]);
    close(handle).unwrap();
    let path = SqliteProvider::new(directory.path(), root).path(workspace);
    let store = arachne_store::Store::open_existing(&path, &root, workspace).unwrap();
    assert!(store.get(b"runtime/pending").unwrap().is_none());
    assert!(store.keys(b"security/").count() > 0);
    drop(store);
    directory.close().unwrap();
}
