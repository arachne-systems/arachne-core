use arachne_runtime::{MemoryProvider, close, describe, execute, record_freshness};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

mod common;

/// A node with its own in-memory record storage.
fn node(secret: u8) -> i64 {
    common::stored(&[secret; 32], &MemoryProvider::default())
}

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|e| e.to_string())
}
fn issue_invitation(handle: i64) -> Value {
    let staged = call(
        handle,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    )
    .unwrap();
    call(
        handle,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )
    .unwrap()["issued_invitation"]
        .clone()
}

#[test]
fn creator_name_is_authenticated_in_invitation_without_creating_join_state() {
    let admin = node(171);
    let invitee = node(172);
    let created = call(
        admin,
        json!({"op":"create_workspace", "display_name":"Alex",
        "workspace_name":"Storm Assessment"}),
    )
    .expect("creation must accept the creator workspace name");
    assert_eq!(created["workspace_name"], "Storm Assessment");
    let invitation = issue_invitation(admin);
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
    use arachne_delivery::{
        PublisherLog,
        inbox::{InboxStage, ObjectInbox},
    };
    use arachne_routing::{PublicationContext, Topic};
    use arachne_security::{PendingJoin, Workspace};
    let root = [173; 32];
    let provider = MemoryProvider::default();
    let mut handle = common::stored(&root, &provider);
    let endpoint: [u8; 32] = serde_json::from_value(serde_json::from_str::<Value>(&arachne_runtime::describe(handle).unwrap()).unwrap()["endpoint_key"].clone()).unwrap();
    let _ = endpoint;
    let secret = iroh::SecretKey::from_bytes(&root);
    let mut creator = Workspace::create_named(
        &arachne_node::IrohEndpointSigner(&secret),
        "Alex",
        Some("Storm Assessment"),
    )
    .unwrap();
    let (registered, invitation, checkpoint) = creator.prepare_invitation(0, false, false).unwrap();
    creator = registered.workspace;
    let jordan_key = arachne_security::EndpointKey::generate().unwrap();
    let pending =
        PendingJoin::from_invitation(&invitation, &checkpoint, &jordan_key, "Jordan").unwrap();
    let add = creator
        .prepare_admission(
            arachne_security::EndpointSigner::endpoint(&jordan_key),
            pending.admission_request().unwrap(),
        )
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
    let mut publisher = PublisherLog::new(&creator).unwrap();
    publisher
        .append(
            context.clone(),
            creator
                .protect_object(
                    context.topic.namespace().as_bytes(),
                    &context.authenticated_bytes(),
                    b"Retained outbound chat",
                )
                .unwrap(),
        )
        .unwrap();
    let packet = member
        .protect_object(
            context.topic.namespace().as_bytes(),
            &context.authenticated_bytes(),
            b"Unread incoming chat",
        )
        .unwrap();
    let InboxStage::Prepared(inbox) = ObjectInbox::new(workspace, creator.epoch())
        .stage(&creator, &context, &packet)
        .unwrap()
    else {
        panic!("pending object missing")
    };
    let original_delivery = inbox.snapshot_with_publisher(&creator, &publisher).unwrap();
    arachne_runtime::harness::seed_workspace(&provider, &creator, Some(&publisher), Some(&inbox))
        .unwrap();
    let restore = |handle: i64| {
        call(
            handle,
            json!({"op":"restore_workspace","workspace":workspace}),
        )
        .unwrap()
    };
    assert_eq!(restore(handle)["workspace_name"], "Storm Assessment");
    // A process loss after staging, before adoption, keeps the accepted name.
    let unsaved = call(
        handle,
        json!({"op":"stage_workspace_name","workspace_name":"Valley Recovery"}),
    )
    .unwrap();
    close(handle).unwrap();
    handle = common::stored(&root, &provider);
    assert_eq!(restore(handle)["workspace_name"], "Storm Assessment");
    assert!(
        call(
            handle,
            json!({"op":"adopt_admission","candidate":unsaved["candidate"]})
        )
        .is_err()
    );
    let renamed = call(
        handle,
        json!({"op":"stage_workspace_name","workspace_name":"Valley Recovery"}),
    )
    .unwrap();
    let mut wrong = bytes(&renamed["candidate"]);
    wrong[36] ^= 1;
    assert!(call(handle, json!({"op":"adopt_admission","candidate":wrong})).is_err());
    call(
        handle,
        json!({"op":"adopt_admission","candidate":renamed["candidate"]}),
    )
    .unwrap();
    assert_eq!(
        bytes(&call(handle, json!({"op":"poll_pending_object"})).unwrap()["payload"]),
        b"Unread incoming chat"
    );
    // The rename kept the pending delivery state byte for byte (a stored
    // value starts with a one-byte tag: 0 is the whole value).
    assert_eq!(
        provider.value(workspace, b"delivery/inbox").unwrap(),
        [&[0u8][..], &original_delivery].concat()
    );
    close(handle).unwrap();
    handle = common::stored(&root, &provider);
    let restored = restore(handle);
    assert_eq!(restored["workspace_name"], "Valley Recovery");
    assert_eq!(restored["epoch"], creator.epoch());
    assert_eq!(restored["members"], 2);
    assert_eq!(
        bytes(&call(handle, json!({"op":"poll_pending_object"})).unwrap()["payload"]),
        b"Unread incoming chat"
    );
    close(handle).unwrap();
}

fn join(admin: i64, member: i64, invitation: &Value) -> Value {
    let pending = call(member, json!({"op":"begin_join","display_name":"Jordan","invitation":invitation["invitation"],"checkpoint":invitation["checkpoint"]})).unwrap();
    let added = call(admin, json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],"request":pending["admission_request"]})).unwrap();
    call(
        admin,
        json!({"op":"adopt_admission","candidate":added["candidate"]}),
    )
    .unwrap();
    let reply = call(admin, json!({"op":"retained_admission","authenticated_endpoint":pending["endpoint"],"request":pending["admission_request"]})).unwrap();
    let joined = call(member, json!({"op":"stage_join","welcome":reply["welcome"],"commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]})).unwrap();
    call(
        member,
        json!({"op":"adopt_join","candidate":joined["candidate"]}),
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
    let admin = node(175);
    let member_storage = MemoryProvider::default();
    let mut member = common::stored(&[176; 32], &member_storage);
    let created = call(
        admin,
        json!({"op":"create_workspace","display_name":"Alex","workspace_name":"Storm Assessment"}),
    )
    .unwrap();
    let invite = issue_invitation(admin);
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
        json!({"op":"adopt_admission","candidate":promotion["candidate"]}),
    )
    .unwrap();
    let change = call(
        member,
        json!({"op":"stage_admission_update","step":promotion["step"]}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"adopt_admission","candidate":change["candidate"]}),
    )
    .unwrap();
    // Storage holds the member's state at this point.
    close(member).unwrap();
    for name in ["Valley Recovery", "Mountain Search"] {
        let change = call(
            admin,
            json!({"op":"stage_workspace_name","workspace_name":name}),
        )
        .unwrap();
        let adopted = call(
            admin,
            json!({"op":"adopt_admission","candidate":change["candidate"]}),
        )
        .unwrap();
        assert_eq!(adopted["epoch"], 3); // Registration and admission come first.
    }
    member = common::stored(&[176; 32], &member_storage);
    call(
        member,
        json!({"op":"restore_workspace","workspace":created["workspace"]}),
    )
    .unwrap();
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
            json!({"op":"adopt_admission","candidate":staged["candidate"]}),
        )
        .unwrap();
        assert_eq!(adopted["workspace_name"], expected);
        assert_eq!(adopted["epoch"], 3); // Registration and admission come first.
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
        json!({"op":"adopt_admission","candidate":renamed["candidate"]}),
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
    let admin = node(179);
    let member = node(180);
    call(
        admin,
        json!({"op":"create_workspace", "display_name":"Alex", "workspace_name":"Storm Assessment"}),
    )
    .unwrap();
    let invite = issue_invitation(admin);
    let identity = join(admin, member, &invite);
    let admin_info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
    let member_info: Value = serde_json::from_str(&describe(member).unwrap()).unwrap();
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
    // The member saves its own update, then the administrator catches up.
    // The rename below must start with both members at the same epoch.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut self_updated = false;
    loop {
        call(admin, json!({"op":"drive_workspace"})).unwrap();
        let value = call(member, json!({"op":"drive_workspace"})).unwrap();
        if value["state"] == "self_update_committed" {
            self_updated = true;
            call(
                member,
                json!({"op":"poll_workspace_presence","announce":true}),
            )
            .unwrap();
        }
        if self_updated
            && call(admin, json!({"op":"member_roster"})).unwrap()["epoch"]
                == call(member, json!({"op":"member_roster"})).unwrap()["epoch"]
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "self-update did not converge: {value}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
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
    let adopted = call(
        admin,
        json!({"op":"adopt_admission","candidate":renamed["candidate"]}),
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
        // The admin's Rust driver, like a host: it saves and adopts what it
        // stages (for example the member's own self-update, B3c).
        let tick = call(admin, json!({"op":"drive_workspace"})).unwrap();
        let _ = tick;
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
}

#[test]
fn rust_workspace_driver_reports_a_stale_name_peer_without_overwriting_local() {
    let admin = node(181);
    let member = node(182);
    call(
        admin,
        json!({"op":"create_workspace", "display_name":"Alex", "workspace_name":"Original"}),
    )
    .unwrap();
    let invite = issue_invitation(admin);
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
        json!({"op":"adopt_admission","candidate":renamed["candidate"]}),
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
    let admin = node(183);
    let member = node(184);
    call(
        admin,
        json!({"op":"create_workspace", "display_name":"Alex", "workspace_name":"Original"}),
    )
    .unwrap();
    let invite = issue_invitation(admin);
    let identity = join(admin, member, &invite);
    let promotion = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"promote","member":identity["member"]["id"]}}),
    )
    .unwrap();
    let promotion = call(
        admin,
        json!({"op":"adopt_admission","candidate":promotion["candidate"]}),
    )
    .unwrap();
    let promoted = call(
        member,
        json!({"op":"stage_admission_update","step":promotion["step"]}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"adopt_admission","candidate":promoted["candidate"]}),
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
            json!({"op":"adopt_admission","candidate":renamed["candidate"]}),
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
    let admin = node(177);
    // The member uses SQLite so the test can put an older, authentic copy of
    // its database back: the stale restore below.
    let member_root = [178; 32];
    let member_dir = common::directory();
    let open_member = || {
        let handle = arachne_runtime::create(Some(&member_root)).unwrap();
        arachne_runtime::attach_storage(
            handle,
            arachne_runtime::StorageConfig::sqlite(member_dir.path(), member_root),
        )
        .unwrap();
        handle
    };
    let mut member = open_member();
    let created = call(
        admin,
        json!({"op":"create_workspace","display_name":"Alex","workspace_name":"Storm Assessment"}),
    )
    .unwrap();
    let invite = issue_invitation(admin);
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
        json!({"op":"adopt_admission","candidate":promotion["candidate"]}),
    )
    .unwrap();
    let promoted = call(
        member,
        json!({"op":"stage_admission_update","step":promotion["step"]}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"adopt_admission","candidate":promoted["candidate"]}),
    )
    .unwrap();
    // Keep a copy of the member's database from before its own rename.
    let workspace: [u8; 32] = serde_json::from_value(created["workspace"].clone()).unwrap();
    let member_path =
        arachne_runtime::SqliteProvider::new(member_dir.path(), member_root).path(workspace);
    let stale = member_dir.path().join("member-stale.db");
    let stale_anchor = record_freshness(member).unwrap();
    close(member).unwrap();
    std::fs::copy(&member_path, &stale).unwrap();
    member = open_member();
    call(
        member,
        json!({"op":"restore_workspace","workspace":workspace,"freshness":stale_anchor.to_bytes().to_vec()}),
    )
    .unwrap();
    // The reopened node may bind a new port.
    let member_node = call(member, json!({"op":"endpoint_info"})).unwrap();
    call(
        admin,
        json!({"op":"add_address_hint","peer":member_node["endpoint_key"],"address":member_node["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();

    let renamed = call(
        member,
        json!({"op":"stage_workspace_name","workspace_name":"Valley Recovery"}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"adopt_admission","candidate":renamed["candidate"]}),
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
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )
    .unwrap();

    let demotion = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"demote","member":member_id}}),
    )
    .unwrap();
    let demotion = call(
        admin,
        json!({"op":"adopt_admission","candidate":demotion["candidate"]}),
    )
    .unwrap();
    close(member).unwrap();
    std::fs::copy(&stale, &member_path).unwrap();
    member = open_member();
    call(
        member,
        json!({"op":"restore_workspace","workspace":created["workspace"],"freshness":stale_anchor.to_bytes().to_vec()}),
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
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
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
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )
    .unwrap();
    assert_eq!(adopted["workspace_name"], "Valley Recovery");
    assert_eq!(adopted["workspace_name_missing_history"], 1);
    assert_eq!(adopted["epoch"], 4); // One more for the link registration.
    let anchor = record_freshness(member).unwrap();
    close(member).unwrap();
    member = open_member();
    let restored = call(
        member,
        json!({"op":"restore_workspace","workspace":created["workspace"],"freshness":anchor.to_bytes().to_vec()}),
    )
    .unwrap();
    assert_eq!(restored["workspace_name"], "Valley Recovery");
    assert_eq!(restored["workspace_name_missing_history"], 1);
    close(admin).unwrap();
    close(member).unwrap();
    member_dir.close().unwrap();
}
