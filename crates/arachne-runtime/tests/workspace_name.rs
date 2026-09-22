use arachne_runtime::{
    close, create, describe, enable_record_storage, execute, execute_stored, save_candidate,
};
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::{Duration, Instant};

mod common;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|e| e.to_string())
}

#[test]
fn creator_name_is_authenticated_in_invitation_without_creating_join_state() {
    let _nodes = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[171; 32])).unwrap();
    let invitee = create(Some(&[172; 32])).unwrap();
    let created = call(
        admin,
        json!({"op":"create_workspace", "display_name":"Alex",
        "workspace_name":"Storm Assessment"}),
    )
    .expect("creation must accept the creator workspace name");
    assert_eq!(created["workspace_name"], "Storm Assessment");
    let invitation = call(admin, json!({"op":"issue_invitation"})).unwrap();
    let inspected = call(
        invitee,
        json!({"op":"inspect_invitation",
        "invitation":invitation["invitation"], "checkpoint":invitation["checkpoint"]}),
    )
    .unwrap();
    assert_eq!(inspected["workspace_name"], "Storm Assessment");
    assert_eq!(inspected["workspace"], created["workspace"]);
    let request =
        json!({"invitation":invitation["invitation"],"checkpoint":invitation["checkpoint"]});
    let stateless: Value = serde_json::from_slice(
        &arachne_runtime::inspect_invitation(&serde_json::to_vec(&request).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(stateless, inspected);
    let mut substituted = request;
    substituted["checkpoint"][10] = json!(substituted["checkpoint"][10].as_u64().unwrap() ^ 1);
    assert!(
        arachne_runtime::inspect_invitation(&serde_json::to_vec(&substituted).unwrap()).is_err()
    );
    let pending = call(
        invitee,
        json!({"op":"begin_join", "display_name":"Jordan",
        "invitation":invitation["invitation"], "checkpoint":invitation["checkpoint"]}),
    )
    .unwrap();
    assert_eq!(pending["workspace_name"], "Storm Assessment");
    close(admin).unwrap();
    close(invitee).unwrap();
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::from_value(value.clone()).unwrap()
}

#[test]
fn rename_preserves_legacy_and_native_pending_delivery_across_interruption() {
    let _nodes = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    use arachne_delivery::{
        PublisherLog,
        inbox::{InboxStage, ObjectInbox},
    };
    use arachne_routing::{PublicationContext, Topic};
    use arachne_runtime::{enable_record_storage, restore_record_storage, save_candidate};
    use arachne_security::{PendingJoin, StorageKey, Workspace};
    let root = [173; 32];
    let mut handle = create(Some(&root)).unwrap();
    let endpoint: [u8; 32] = serde_json::from_value(serde_json::from_str::<Value>(&arachne_runtime::describe(handle).unwrap()).unwrap()["endpoint_key"].clone()).unwrap();
    let creator = Workspace::create_named(endpoint, "Alex", Some("Storm Assessment")).unwrap();
    let (invitation, checkpoint) = creator.issue_invitation().unwrap();
    let pending =
        PendingJoin::from_invitation(&invitation, &checkpoint, [174; 32], "Jordan").unwrap();
    let add = creator
        .prepare_admission([174; 32], pending.admission_request().unwrap())
        .unwrap();
    let mut proof = pending.join_proof().unwrap();
    proof.apply_add(&add.authorization, &add.commit).unwrap();
    let mut member = pending.prepare_workspace(&proof, &add.welcome).unwrap();
    let mut creator = add.workspace;
    let workspace = creator.id();
    let context = PublicationContext {
        workspace,
        revision: 2,
        topic: Topic::new("chat/messages").unwrap(),
        id: [1; 16],
        sequence: std::num::NonZeroU64::new(1),
    };
    let mut publisher =
        PublisherLog::new(workspace, creator.member().unwrap().id(), creator.epoch());
    publisher
        .append(
            context.clone(),
            creator
                .protect_object(&context.authenticated_bytes(), b"Retained outbound chat")
                .unwrap(),
        )
        .unwrap();
    let packet = member
        .protect_object(&context.authenticated_bytes(), b"Unread incoming chat")
        .unwrap();
    let InboxStage::Prepared(inbox) = ObjectInbox::new(workspace, creator.epoch())
        .stage(&creator, &context, &packet)
        .unwrap()
    else {
        panic!("pending object missing")
    };
    let original_delivery = inbox.snapshot_with_publisher(&creator, &publisher).unwrap();
    let key = StorageKey::derive(&root).unwrap();
    let original = inbox.seal(&creator, &key, &publisher).unwrap();
    call(
        handle,
        json!({"op":"restore_workspace","workspace":workspace,"snapshot":original}),
    )
    .unwrap();
    let renamed = call(
        handle,
        json!({"op":"stage_workspace_name","workspace_name":"Valley Recovery"}),
    )
    .unwrap();
    assert!(bytes(&renamed["snapshot"]).starts_with(b"DFWB\x01"));
    let (owner, log, restored_inbox) =
        ObjectInbox::restore(&key, endpoint, workspace, &bytes(&renamed["snapshot"])).unwrap();
    assert_eq!(owner.epoch_fingerprint(), creator.epoch_fingerprint());
    assert_eq!(
        restored_inbox
            .snapshot_with_publisher(&owner, &log)
            .unwrap(),
        original_delivery
    );
    assert_eq!(
        restored_inbox
            .pending(&owner)
            .unwrap()
            .unwrap()
            .message
            .payload,
        b"Unread incoming chat"
    );
    call(
        handle,
        json!({"op":"adopt_admission","snapshot":renamed["snapshot"]}),
    )
    .unwrap();
    assert_eq!(
        bytes(&call(handle, json!({"op":"poll_pending_object"})).unwrap()["payload"]),
        b"Unread incoming chat"
    );
    close(handle).unwrap();

    let directory = common::directory();
    let path = directory.path().join("workspace.db");
    handle = create(Some(&root)).unwrap();
    call(
        handle,
        json!({"op":"restore_workspace","workspace":workspace,"snapshot":original}),
    )
    .unwrap();
    enable_record_storage(handle, &path, &root).unwrap();
    let unsaved = call(
        handle,
        json!({"op":"stage_workspace_name","workspace_name":"Valley Recovery"}),
    )
    .unwrap();
    assert!(
        call(
            handle,
            json!({"op":"adopt_admission","snapshot":unsaved["snapshot"]})
        )
        .is_err()
    );
    close(handle).unwrap();
    handle = create(Some(&root)).unwrap();
    assert_eq!(
        restore_record_storage(handle, &path, &root, workspace).unwrap()["workspace_name"],
        "Storm Assessment"
    );
    let renamed = call(
        handle,
        json!({"op":"stage_workspace_name","workspace_name":"Valley Recovery"}),
    )
    .unwrap();
    let mut wrong = bytes(&renamed["snapshot"]);
    wrong[36] ^= 1;
    assert!(save_candidate(handle, &wrong).is_err());
    save_candidate(handle, &bytes(&renamed["snapshot"])).unwrap();
    save_candidate(handle, &bytes(&renamed["snapshot"])).unwrap();
    // A process loss after commit but before adoption restores the accepted name.
    close(handle).unwrap();
    let store = arachne_store::Store::open(&path, &root, workspace).unwrap();
    assert_eq!(
        store.get(b"delivery/inbox").unwrap().unwrap().as_slice(),
        original_delivery
    );
    drop(store);
    handle = create(Some(&root)).unwrap();
    let restored = restore_record_storage(handle, &path, &root, workspace).unwrap();
    assert_eq!(restored["workspace_name"], "Valley Recovery");
    assert_eq!(restored["epoch"], creator.epoch());
    assert_eq!(restored["members"], 2);
    assert_eq!(
        bytes(&call(handle, json!({"op":"poll_pending_object"})).unwrap()["payload"]),
        b"Unread incoming chat"
    );
    close(handle).unwrap();
    directory.close().unwrap();
}

fn join(admin: i64, member: i64, invitation: &Value) -> Value {
    let pending = call(member, json!({"op":"begin_join","display_name":"Jordan","invitation":invitation["invitation"],"checkpoint":invitation["checkpoint"]})).unwrap();
    let added = call(admin, json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],"request":pending["admission_request"]})).unwrap();
    call(
        admin,
        json!({"op":"adopt_admission","snapshot":added["snapshot"]}),
    )
    .unwrap();
    let reply = call(admin, json!({"op":"retained_admission","authenticated_endpoint":pending["endpoint"],"request":pending["admission_request"]})).unwrap();
    let joined = call(member, json!({"op":"stage_join","welcome":reply["welcome"],"commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]})).unwrap();
    call(
        member,
        json!({"op":"adopt_join","snapshot":joined["snapshot"]}),
    )
    .unwrap();
    pending
}

fn poll_reply(responder: i64, receiver: i64) -> Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        call(responder, json!({"op":"poll_admission"})).unwrap();
        let reply = call(receiver, json!({"op":"poll_membership_update"})).unwrap();
        if reply != Value::Null {
            return reply;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "name update timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn existing_control_poll_pages_names_and_discards_reply_for_old_name_head() {
    let _nodes = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[175; 32])).unwrap();
    let mut member = create(Some(&[176; 32])).unwrap();
    let created = call(
        admin,
        json!({"op":"create_workspace","display_name":"Alex","workspace_name":"Storm Assessment"}),
    )
    .unwrap();
    let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
    let identity = join(admin, member, &invite);
    assert!(
        call(
            member,
            json!({"op":"stage_workspace_name","workspace_name":"Unauthorized"})
        )
        .is_err()
    );
    let promotion = call(admin, json!({"op":"stage_management","action":{"kind":"promote","member":identity["member"]["id"]}})).unwrap();
    let promotion = call(
        admin,
        json!({"op":"adopt_admission","snapshot":promotion["snapshot"]}),
    )
    .unwrap();
    let change = call(
        member,
        json!({"op":"stage_admission_update","step":promotion["step"]}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"adopt_admission","snapshot":change["snapshot"]}),
    )
    .unwrap();
    let saved = call(member, json!({"op":"seal_workspace"})).unwrap();
    close(member).unwrap();
    for name in ["Valley Recovery", "Mountain Search"] {
        let change = call(
            admin,
            json!({"op":"stage_workspace_name","workspace_name":name}),
        )
        .unwrap();
        let adopted = call(
            admin,
            json!({"op":"adopt_admission","snapshot":change["snapshot"]}),
        )
        .unwrap();
        assert_eq!(adopted["epoch"], 2);
    }
    member = create(Some(&[176; 32])).unwrap();
    call(member, json!({"op":"restore_workspace","workspace":created["workspace"],"snapshot":saved["snapshot"]})).unwrap();
    call(member, json!({"op":"add_address_hint","peer":invite["peer"],"address":invite["address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")})).unwrap();
    for expected in ["Valley Recovery", "Mountain Search"] {
        call(
            member,
            json!({"op":"fetch_membership_update","peer":invite["peer"]}),
        )
        .unwrap();
        let next = poll_reply(admin, member);
        assert_eq!(next["state"], "workspace_name_update_available");
        let staged = call(
            member,
            json!({"op":"stage_workspace_name_update","name_record":next["name_record"]}),
        )
        .unwrap();
        let adopted = call(
            member,
            json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
        )
        .unwrap();
        assert_eq!(adopted["workspace_name"], expected);
        assert_eq!(adopted["epoch"], 2);
    }
    call(
        member,
        json!({"op":"fetch_membership_update","peer":invite["peer"]}),
    )
    .unwrap();
    let renamed = call(
        member,
        json!({"op":"stage_workspace_name","workspace_name":"Southern Sector"}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"adopt_admission","snapshot":renamed["snapshot"]}),
    )
    .unwrap();
    assert_eq!(
        poll_reply(admin, member)["state"],
        "membership_update_stale"
    );
    assert_eq!(
        call(member, json!({"op":"member_roster"})).unwrap()["workspace_name"],
        "Southern Sector"
    );
    close(admin).unwrap();
    close(member).unwrap();
}

#[test]
fn rust_workspace_driver_converges_same_epoch_name_from_presence() {
    let _nodes = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[179; 32])).unwrap();
    let member = create(Some(&[180; 32])).unwrap();
    call(
        admin,
        json!({"op":"create_workspace", "display_name":"Alex", "workspace_name":"Storm Assessment"}),
    )
    .unwrap();
    let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
    let identity = join(admin, member, &invite);
    let admin_info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
    let member_info: Value = serde_json::from_str(&describe(member).unwrap()).unwrap();
    let admin_dir = common::directory();
    let member_dir = common::directory();
    enable_record_storage(
        admin,
        &admin_dir.path().join("admin.db"),
        &[179; 32],
    )
    .unwrap();
    enable_record_storage(
        member,
        &member_dir.path().join("member.db"),
        &[180; 32],
    )
    .unwrap();
    let loopback = |info: &Value| {
        info["bound_address"]
            .as_str()
            .unwrap()
            .replace("0.0.0.0:", "127.0.0.1:")
    };
    call(
        admin,
        json!({"op":"add_address_hint","peer":member_info["endpoint_key"],"address":loopback(&member_info)}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"add_address_hint","peer":admin_info["endpoint_key"],"address":loopback(&admin_info)}),
    )
    .unwrap();
    // Consume the initial announcement so the rename below must trigger its
    // own native presence packet.
    call(
        admin,
        json!({"op":"poll_workspace_presence","announce":true}),
    )
    .unwrap();
    let member_epoch = call(member, json!({"op":"member_roster"})).unwrap()["epoch"].clone();

    let renamed = call(
        admin,
        json!({"op":"stage_workspace_name","workspace_name":"Search and Recovery"}),
    )
    .unwrap();
    let snapshot = bytes(&renamed["snapshot"]);
    save_candidate(admin, &snapshot).unwrap();
    let adopted: Value = serde_json::from_slice(
        &execute_stored(admin, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap()[0],
    )
    .unwrap();
    assert_eq!(adopted["workspace_name"], "Search and Recovery");
    assert_eq!(adopted["epoch"], member_epoch);

    // The native presence announcement carries the changed name head. The
    // member's Rust driver must query, persist and adopt it without a host
    // peer walk or a direct poll_membership_update call.
    let deadline = Instant::now() + Duration::from_secs(5);
    let committed = loop {
        call(member, json!({"op":"poll_admission"})).unwrap();
        call(admin, json!({"op":"poll_workspace_presence"})).unwrap();
        call(admin, json!({"op":"poll_admission"})).unwrap();
        let value = call(member, json!({"op":"drive_workspace"})).unwrap();
        if value["state"] == "workspace_name_committed" {
            break value;
        }
        assert!(Instant::now() < deadline, "name did not converge: {value}");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(committed["workspace_name"], "Search and Recovery");
    assert_eq!(
        call(member, json!({"op":"member_roster"})).unwrap()["workspace_name"],
        "Search and Recovery"
    );
    assert_eq!(identity["endpoint"], member_info["endpoint_key"]);
    close(admin).unwrap();
    close(member).unwrap();
    admin_dir.close().unwrap();
    member_dir.close().unwrap();
}

#[test]
fn rust_workspace_driver_reports_a_stale_name_peer_without_overwriting_local() {
    let _nodes = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[181; 32])).unwrap();
    let member = create(Some(&[182; 32])).unwrap();
    call(
        admin,
        json!({"op":"create_workspace", "display_name":"Alex", "workspace_name":"Original"}),
    )
    .unwrap();
    let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
    let identity = join(admin, member, &invite);
    let member_info: Value = serde_json::from_str(&describe(member).unwrap()).unwrap();
    call(
        admin,
        json!({"op":"add_address_hint","peer":member_info["endpoint_key"],"address":member_info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    let renamed = call(
        admin,
        json!({"op":"stage_workspace_name","workspace_name":"Current"}),
    )
    .unwrap();
    call(
        admin,
        json!({"op":"adopt_admission","snapshot":renamed["snapshot"]}),
    )
    .unwrap();
    call(
        admin,
        json!({"op":"fetch_membership_update","peer":identity["endpoint"]}),
    )
    .unwrap();
    let result = poll_reply(member, admin);
    assert_eq!(result["state"], "workspace_name_peer_behind", "{result}");
    assert_eq!(result["local_workspace_name"], "Current");
    assert_eq!(
        call(admin, json!({"op":"member_roster"})).unwrap()["workspace_name"],
        "Current"
    );
    assert_eq!(
        call(member, json!({"op":"member_roster"})).unwrap()["workspace_name"],
        "Original"
    );
    close(admin).unwrap();
    close(member).unwrap();
}

#[test]
fn rust_workspace_driver_reports_equal_revision_name_conflict_without_overwriting_local() {
    let _nodes = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[183; 32])).unwrap();
    let member = create(Some(&[184; 32])).unwrap();
    call(
        admin,
        json!({"op":"create_workspace", "display_name":"Alex", "workspace_name":"Original"}),
    )
    .unwrap();
    let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
    let identity = join(admin, member, &invite);
    let promotion = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"promote","member":identity["member"]["id"]}}),
    )
    .unwrap();
    let promotion = call(
        admin,
        json!({"op":"adopt_admission","snapshot":promotion["snapshot"]}),
    )
    .unwrap();
    let promoted = call(
        member,
        json!({"op":"stage_admission_update","step":promotion["step"]}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"adopt_admission","snapshot":promoted["snapshot"]}),
    )
    .unwrap();
    let member_info: Value = serde_json::from_str(&describe(member).unwrap()).unwrap();
    call(
        admin,
        json!({"op":"add_address_hint","peer":member_info["endpoint_key"],"address":member_info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    let admin_info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
    call(
        member,
        json!({"op":"add_address_hint","peer":admin_info["endpoint_key"],"address":admin_info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    for (handle, name) in [(admin, "Alpha"), (member, "Bravo")] {
        let renamed = call(
            handle,
            json!({"op":"stage_workspace_name","workspace_name":name}),
        )
        .unwrap();
        call(
            handle,
            json!({"op":"adopt_admission","snapshot":renamed["snapshot"]}),
        )
        .unwrap();
    }
    call(
        admin,
        json!({"op":"fetch_membership_update","peer":member_info["endpoint_key"]}),
    )
    .unwrap();
    let result = poll_reply(member, admin);
    assert_eq!(result["state"], "workspace_name_conflict", "{result}");
    assert_eq!(result["local_workspace_name"], "Alpha");
    assert_eq!(
        call(admin, json!({"op":"member_roster"})).unwrap()["workspace_name"],
        "Alpha"
    );
    assert_eq!(
        call(member, json!({"op":"member_roster"})).unwrap()["workspace_name"],
        "Bravo"
    );
    close(admin).unwrap();
    close(member).unwrap();
}

#[test]
fn iroh_name_checkpoint_recovers_after_renaming_admin_is_demoted() {
    let _nodes = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[177; 32])).unwrap();
    let mut member = create(Some(&[178; 32])).unwrap();
    let created = call(
        admin,
        json!({"op":"create_workspace","display_name":"Alex","workspace_name":"Storm Assessment"}),
    )
    .unwrap();
    let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
    let identity = join(admin, member, &invite);
    let member_node = call(member, json!({"op":"endpoint_info"})).unwrap();
    call(
        admin,
        json!({"op":"add_address_hint","peer":member_node["endpoint_key"],"address":member_node["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    let member_id = identity["member"]["id"].clone();
    let promotion = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"promote","member":member_id}}),
    )
    .unwrap();
    let promotion = call(
        admin,
        json!({"op":"adopt_admission","snapshot":promotion["snapshot"]}),
    )
    .unwrap();
    let promoted = call(
        member,
        json!({"op":"stage_admission_update","step":promotion["step"]}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"adopt_admission","snapshot":promoted["snapshot"]}),
    )
    .unwrap();
    let stale = call(member, json!({"op":"seal_workspace"})).unwrap();

    let renamed = call(
        member,
        json!({"op":"stage_workspace_name","workspace_name":"Valley Recovery"}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"adopt_admission","snapshot":renamed["snapshot"]}),
    )
    .unwrap();
    call(
        admin,
        json!({"op":"fetch_membership_update","peer":identity["endpoint"]}),
    )
    .unwrap();
    let name = poll_reply(member, admin);
    assert_eq!(name["state"], "workspace_name_update_available");
    let staged = call(
        admin,
        json!({"op":"stage_workspace_name_update","name_record":name["name_record"]}),
    )
    .unwrap();
    call(
        admin,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap();

    let demotion = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"demote","member":member_id}}),
    )
    .unwrap();
    let demotion = call(
        admin,
        json!({"op":"adopt_admission","snapshot":demotion["snapshot"]}),
    )
    .unwrap();
    close(member).unwrap();
    member = create(Some(&[178; 32])).unwrap();
    call(
        member,
        json!({"op":"restore_workspace","workspace":created["workspace"],"snapshot":stale["snapshot"]}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"add_address_hint","peer":invite["peer"],"address":invite["address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"fetch_membership_update","peer":invite["peer"]}),
    )
    .unwrap();
    let membership = poll_reply(admin, member);
    assert_eq!(membership["state"], "membership_update_available");
    assert_eq!(membership["step"], demotion["step"]);
    let staged = call(
        member,
        json!({"op":"stage_admission_update","step":membership["step"]}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap();

    call(
        member,
        json!({"op":"fetch_membership_update","peer":invite["peer"]}),
    )
    .unwrap();
    let checkpoint = poll_reply(admin, member);
    assert_eq!(checkpoint["state"], "workspace_name_checkpoint_available");
    let staged = call(
        member,
        json!({"op":"stage_workspace_name_checkpoint","name_checkpoint":checkpoint["name_checkpoint"]}),
    )
    .unwrap();
    assert_eq!(staged["name_history_missing_added"], 1);
    assert_eq!(staged["name_history_missing"], 1);
    let adopted = call(
        member,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap();
    assert_eq!(adopted["workspace_name"], "Valley Recovery");
    assert_eq!(adopted["workspace_name_missing_history"], 1);
    assert_eq!(adopted["epoch"], 3);
    close(member).unwrap();
    member = create(Some(&[178; 32])).unwrap();
    let restored = call(
        member,
        json!({"op":"restore_workspace","workspace":created["workspace"],"snapshot":staged["snapshot"]}),
    )
    .unwrap();
    assert_eq!(restored["workspace_name"], "Valley Recovery");
    assert_eq!(restored["workspace_name_missing_history"], 1);
    close(admin).unwrap();
    close(member).unwrap();
}
