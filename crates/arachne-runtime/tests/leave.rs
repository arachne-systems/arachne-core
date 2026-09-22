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

fn join(owner: i64, joiner: i64, invite: &Value, display_name: &str) {
    let request = call(
        joiner,
        json!({"op":"begin_join","display_name":display_name,
        "invitation":invite["invitation"],"checkpoint":invite["checkpoint"]}),
    )
    .unwrap();
    let staged = call(
        owner,
        json!({"op":"stage_admission","authenticated_endpoint":request["endpoint"],"request":request["admission_request"]}),
    )
    .unwrap();
    call(
        owner,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap();
    let reply = call(
        owner,
        json!({"op":"retained_admission","authenticated_endpoint":request["endpoint"],"request":request["admission_request"]}),
    )
    .unwrap();
    let staged = call(
        joiner,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}),
    )
    .unwrap();
    call(
        joiner,
        json!({"op":"adopt_join","snapshot":staged["snapshot"]}),
    )
    .unwrap();
}

fn wait_for_offer(owner: i64) -> Value {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let value = call(owner, json!({"op":"poll_membership_offer"})).unwrap();
        if !value.is_null() {
            return value;
        }
        assert!(Instant::now() < until, "membership handoff acknowledgement timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_offer_result(owner: i64) -> Result<Value, String> {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match call(owner, json!({"op":"poll_membership_offer"})) {
            Ok(value) if value.is_null() => {
                assert!(Instant::now() < until, "membership offer response timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

fn drive_until_work(handle: i64) -> Value {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let value = call(handle, json!({"op":"drive_workspace"})).unwrap();
        if value.get("state").is_some() {
            return value;
        }
        assert!(Instant::now() < until, "workspace driver did not observe work");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn self_member_id(handle: i64) -> [u8; 32] {
    let roster = call(handle, json!({"op":"member_roster"})).unwrap();
    roster["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["self"] == true)
        .and_then(|member| member["id"].as_array())
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn offer_and_drive(owner: i64, peer: i64, after: u64) {
    let owner_roster = call(owner, json!({"op":"member_roster"})).unwrap();
    let peer_info = info(peer);
    let pending = call(
        owner,
        json!({"op":"offer_membership_update","peer":peer_info["endpoint_key"],"after":after}),
    )
    .unwrap();
    assert_eq!(pending["state"], "membership_offer_pending", "offer owner={owner} peer={peer} after={after}: {pending}; owner_roster={owner_roster}; peer_info={peer_info}");
    assert_eq!(drive_until_work(peer)["state"], "workspace_committed");
    assert_eq!(wait_for_offer(owner)["state"], "membership_offer_finished");
}

fn adopt_candidate(handle: i64, staged: &Value) -> Value {
    let snapshot = serde_json::from_value::<Vec<u8>>(staged["snapshot"].clone()).unwrap();
    save_candidate(handle, &snapshot).unwrap();
    call(handle, json!({"op":"adopt_admission","snapshot":staged["snapshot"]})).unwrap()
}

#[test]
fn administrator_handoff_acknowledges_after_successor_adopts_then_allows_leave() {
    let admin = create(Some(&[73; 32])).unwrap();
    let successor = create(Some(&[74; 32])).unwrap();
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Original admin"}),
    )
    .unwrap();
    let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
    join(admin, successor, &invite, "Successor");
    let dir = common::directory();
    enable_record_storage(
        successor,
        &dir.path().join("successor.db"),
        &[74; 32],
    )
    .unwrap();
    route(admin, successor);

    let before_promotion = call(admin, json!({"op":"member_roster"})).unwrap();
    let successor_id = before_promotion["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["self"] == false)
        .and_then(|member| member["id"].as_array())
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect::<Vec<_>>();
    let successor_id: [u8; 32] = successor_id.try_into().unwrap();
    let old_epoch = before_promotion["epoch"].as_u64().unwrap();

    let abandoned = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"promote","member":successor_id}}),
    )
    .unwrap();
    assert!(call(admin, json!({"op":"member_roster"})).is_err());
    assert_eq!(
        call(admin, json!({"op":"discard_workspace_candidate"})).unwrap()["discarded"],
        true
    );
    assert_eq!(call(admin, json!({"op":"member_roster"})).unwrap()["epoch"], old_epoch);
    assert_eq!(abandoned["state"], "awaiting_save");

    let promotion = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"promote","member":successor_id}}),
    )
    .unwrap();
    let successor_endpoint = info(successor)["endpoint_key"].clone();
    let pending = call(
        admin,
        json!({"op":"offer_staged_membership_update","peer":successor_endpoint}),
    )
    .unwrap();
    assert_eq!(pending["state"], "membership_offer_pending");
    // The acknowledgement is deliberately not available until the successor
    // has received, saved, and adopted the promoted membership.
    assert!(call(admin, json!({"op":"poll_membership_offer"}))
        .unwrap()
        .is_null());

    let offered = drive_until_work(successor);
    assert_eq!(offered["state"], "workspace_committed");
    assert_eq!(offered["epoch"], old_epoch + 1);
    assert_eq!(offered["reply_queued"], true);
    assert_eq!(
        wait_for_offer(admin)["state"],
        "membership_offer_finished"
    );
    let promoted = call(
        admin,
        json!({"op":"adopt_admission","snapshot":promotion["snapshot"]}),
    )
    .unwrap();
    assert_eq!(promoted["epoch"], old_epoch + 1);

    let leaving = std::thread::spawn(move || {
        call(
            admin,
            json!({"op":"leave_via_peer","peer":successor_endpoint}),
        )
    });
    let staged = incoming(successor);
    assert_eq!(staged["state"], "awaiting_save");
    assert!(!leaving.is_finished(), "departure completed before the peer adopted it");
    let snapshot = serde_json::from_value::<Vec<u8>>(staged["snapshot"].clone()).unwrap();
    save_candidate(successor, &snapshot).unwrap();
    call(
        successor,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap();
    assert_eq!(
        call(successor, json!({"op":"send_admission_reply"})).unwrap()["queued"],
        true
    );
    assert_eq!(
        call(successor, json!({"op":"member_roster"})).unwrap()["members"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let removed = leaving.join().unwrap().unwrap();
    assert_eq!(removed["removed"], true);
    assert_eq!(
        call(
            admin,
            json!({"op":"adopt_admission","snapshot":removed["snapshot"]}),
        )
        .unwrap()["state"],
        "removed"
    );

    close(successor).unwrap();
    dir.close().unwrap();
}

#[test]
fn three_member_leave_converges_through_successive_administrator_handoffs() {
    let admin = create(Some(&[101; 32])).unwrap();
    let successor = create(Some(&[102; 32])).unwrap();
    let third = create(Some(&[103; 32])).unwrap();
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Alpha"}),
    )
    .unwrap();
    let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
    join(admin, successor, &invite, "Bravo");
    let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
    join(admin, third, &invite, "Charlie");

    let dir = common::directory();
    enable_record_storage(admin, &dir.path().join("alpha.db"), &[101; 32]).unwrap();
    enable_record_storage(successor, &dir.path().join("bravo.db"), &[102; 32]).unwrap();
    enable_record_storage(third, &dir.path().join("charlie.db"), &[103; 32]).unwrap();
    route(admin, successor);
    route(successor, admin);
    route(admin, third);
    route(third, admin);
    route(successor, third);
    route(third, successor);

    let successor_id = self_member_id(successor);
    let third_id = self_member_id(third);
    let failed_promotion = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"promote","member":successor_id}}),
    )
    .unwrap();
    let offer = call(
        admin,
        json!({"op":"offer_staged_membership_update","peer":info(successor)["endpoint_key"]}),
    )
    .unwrap();
    assert_eq!(offer["state"], "membership_offer_pending");
    let poll = std::thread::spawn(move || wait_for_offer_result(admin));
    assert_eq!(drive_until_work(successor)["state"], "membership_replied");
    let rejected = poll.join().unwrap();
    assert!(rejected.is_err(), "stale peer unexpectedly accepted handoff: {rejected:?}");
    assert_eq!(
        call(admin, json!({"op":"discard_workspace_candidate"})).unwrap()["discarded"],
        true
    );
    assert_eq!(failed_promotion["state"], "awaiting_save");

    // The second join advances the creator while the first member still has
    // the previous accepted view. Reconcile that view before any management.
    offer_and_drive(admin, successor, 1);
    let before_promotion = call(admin, json!({"op":"member_roster"})).unwrap();
    assert_eq!(before_promotion["epoch"], 2);
    let before_promotion_epoch = before_promotion["epoch"].as_u64().unwrap();

    let promotion = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"promote","member":successor_id}}),
    )
    .unwrap();
    adopt_candidate(admin, &promotion);
    offer_and_drive(admin, successor, before_promotion_epoch);
    offer_and_drive(admin, third, before_promotion_epoch);

    let leaving = std::thread::spawn(move || {
        call(
            admin,
            json!({"op":"leave_via_peer","peer":info(successor)["endpoint_key"]}),
        )
    });
    let committed = drive_until_work(successor);
    assert_eq!(committed["state"], "workspace_committed");
    assert_eq!(committed["members"], 2);
    let removed = leaving.join().unwrap().unwrap();
    assert_eq!(removed["removed"], true);
    adopt_candidate(admin, &removed);
    offer_and_drive(successor, third, before_promotion_epoch + 1);

    let after_admin_leave = call(successor, json!({"op":"member_roster"})).unwrap();
    assert_eq!(after_admin_leave["epoch"], before_promotion_epoch + 2);
    assert_eq!(after_admin_leave["members"].as_array().unwrap().len(), 2);
    assert!(after_admin_leave["members"]
        .as_array()
        .unwrap()
        .iter()
        .any(|member| member["self"] == true && member["administrator"] == true));

    let promotion = call(
        successor,
        json!({"op":"stage_management","action":{"kind":"promote","member":third_id}}),
    )
    .unwrap();
    adopt_candidate(successor, &promotion);
    offer_and_drive(successor, third, before_promotion_epoch + 2);

    let leaving = std::thread::spawn(move || {
        call(
            successor,
            json!({"op":"leave_via_peer","peer":info(third)["endpoint_key"]}),
        )
    });
    let committed = drive_until_work(third);
    assert_eq!(committed["state"], "workspace_committed");
    assert_eq!(committed["members"], 1);
    let removed = leaving.join().unwrap().unwrap();
    assert_eq!(removed["removed"], true);
    assert_eq!(adopt_candidate(successor, &removed)["state"], "removed");

    let final_roster = call(third, json!({"op":"member_roster"})).unwrap();
    assert_eq!(final_roster["epoch"], before_promotion_epoch + 4);
    assert_eq!(final_roster["members"].as_array().unwrap().len(), 1);
    assert_eq!(
        final_roster["members"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|member| member["administrator"] == true)
            .count(),
        1
    );
    assert_eq!(final_roster["members"][0]["self"], true);
    assert_eq!(final_roster["members"][0]["administrator"], true);

    close(third).unwrap();
    dir.close().unwrap();
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
