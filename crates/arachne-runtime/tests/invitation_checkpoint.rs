use arachne_runtime::{
    close, create, describe, enable_record_storage, execute, restore_record_storage, save_candidate,
};
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::{Duration, Instant};

mod common;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|error| error.to_string())
}

fn endpoint(handle: i64) -> Value {
    serde_json::from_str(&describe(handle).unwrap()).unwrap()
}

fn serve_once(handle: i64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let event = call(handle, json!({"op":"poll_admission"})).unwrap();
        if event != Value::Null {
            return event;
        }
        assert!(
            Instant::now() < deadline,
            "checkpoint request was not received"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn fetches_only_the_exact_invitation_checkpoint_over_authenticated_iroh() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[201; 32])).unwrap();
    let joiner = create(Some(&[202; 32])).unwrap();
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator","workspace_name":"Ridge Team"}),
    )
    .unwrap();
    let invitation = call(admin, json!({"op":"issue_invitation"})).unwrap();
    let admin_node = endpoint(admin);
    call(
        joiner,
        json!({"op":"add_address_hint","peer":admin_node["endpoint_key"],
            "address":admin_node["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();

    let peer = admin_node["endpoint_key"].clone();
    let expected_peer = peer.clone();
    let bearer = invitation["invitation"].clone();
    let fetch = std::thread::spawn(move || {
        call(
            joiner,
            json!({"op":"fetch_invitation_checkpoint","peer":peer,"invitation":bearer}),
        )
    });
    // An invitation checkpoint is an inquiry (ADR 0010): the committed view
    // answers it and the host sees no event.
    let fetched = fetch.join().unwrap().unwrap();
    assert_eq!(fetched["checkpoint"], invitation["checkpoint"]);

    let peer = admin_node["endpoint_key"].clone();
    let bearer = invitation["invitation"].clone();
    let fallback = std::thread::spawn(move || {
        call(
            joiner,
            json!({"op":"fetch_invitation_checkpoint","peers":[vec![250u8; 32],peer],"invitation":bearer}),
        )
    });
    let fetched = fallback.join().unwrap().unwrap();
    assert_eq!(fetched["peer"], expected_peer);
    assert_eq!(fetched["checkpoint"], invitation["checkpoint"]);

    let renamed = call(
        admin,
        json!({"op":"stage_workspace_name","workspace_name":"Ridge Team North"}),
    )
    .unwrap();
    call(
        admin,
        json!({"op":"adopt_admission","snapshot":renamed["snapshot"]}),
    )
    .unwrap();
    let peer = admin_node["endpoint_key"].clone();
    let bearer = invitation["invitation"].clone();
    let stale = std::thread::spawn(move || {
        call(
            joiner,
            json!({"op":"fetch_invitation_checkpoint","peer":peer,"invitation":bearer}),
        )
    });
    assert!(stale.join().unwrap().is_err());

    let outsider = create(Some(&[203; 32])).unwrap();
    let outsider_node = endpoint(outsider);
    let requester = create(Some(&[204; 32])).unwrap();
    call(
        requester,
        json!({"op":"add_address_hint","peer":outsider_node["endpoint_key"],
            "address":outsider_node["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    let peer = outsider_node["endpoint_key"].clone();
    let bearer = invitation["invitation"].clone();
    let substituted = std::thread::spawn(move || {
        call(
            requester,
            json!({"op":"fetch_invitation_checkpoint","peer":peer,"invitation":bearer}),
        )
    });
    let denied = serve_once(outsider);
    assert_eq!(denied["state"], "invitation_checkpoint_replied");
    assert_eq!(denied["accepted"], false);
    assert!(substituted.join().unwrap().is_err());

    for handle in [admin, joiner, outsider, requester] {
        close(handle).unwrap();
    }
}

#[test]
fn ordinary_member_serves_the_checkpoint_it_joined_from_after_issuer_closes() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[211; 32])).unwrap();
    let mut helper = create(Some(&[212; 32])).unwrap();
    let late = create(Some(&[213; 32])).unwrap();
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator","workspace_name":"Event Team"}),
    )
    .unwrap();
    let invitation = call(admin, json!({"op":"issue_invitation"})).unwrap();
    let pending = call(
        helper,
        json!({"op":"begin_join","display_name":"First member","invitation":invitation["invitation"],
            "checkpoint":invitation["checkpoint"]}),
    )
    .unwrap();
    let staged = call(
        admin,
        json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],
            "request":pending["admission_request"]}),
    )
    .unwrap();
    call(
        admin,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap();
    let reply = call(
        admin,
        json!({"op":"retained_admission","authenticated_endpoint":pending["endpoint"],
            "request":pending["admission_request"]}),
    )
    .unwrap();
    let joined = call(
        helper,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":[{
            "commit":reply["commit"],"authorization":reply["authorization"]}]}),
    )
    .unwrap();
    call(
        helper,
        json!({"op":"adopt_join","snapshot":joined["snapshot"]}),
    )
    .unwrap();
    close(admin).unwrap();
    close(helper).unwrap();
    helper = create(Some(&[212; 32])).unwrap();
    call(
        helper,
        json!({"op":"restore_workspace","workspace":invitation["workspace"],
            "snapshot":joined["snapshot"]}),
    )
    .unwrap();

    let helper_node = endpoint(helper);
    call(
        late,
        json!({"op":"add_address_hint","peer":helper_node["endpoint_key"],
            "address":helper_node["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    let peer = helper_node["endpoint_key"].clone();
    let bearer = invitation["invitation"].clone();
    let fetch = std::thread::spawn(move || {
        call(
            late,
            json!({"op":"fetch_invitation_checkpoint","peer":peer,"invitation":bearer}),
        )
    });
    // An invitation checkpoint is an inquiry (ADR 0010): the committed view
    // answers it and the host sees no event.
    let fetched = fetch.join().unwrap().unwrap();
    assert_eq!(fetched["checkpoint"], invitation["checkpoint"]);
    call(
        late,
        json!({"op":"begin_join","display_name":"Late member","invitation":invitation["invitation"],
            "checkpoint":fetched["checkpoint"]}),
    )
    .unwrap();
    let peer = helper_node["endpoint_key"].clone();
    let retry_peer = peer.clone();
    let admission = std::thread::spawn(move || {
        call(late, json!({"op":"request_admission","peer":peer})).unwrap()
    });
    assert_eq!(serve_once(helper), json!({"state":"admission_queued"}));
    let staged = serve_once(helper);
    assert_eq!(staged["state"], "awaiting_save");
    call(
        helper,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap();
    let retry = std::thread::spawn(move || {
        call(late, json!({"op":"request_admission","peer":retry_peer})).unwrap()
    });
    // The result is retained, so this retry is an inquiry (ADR 0010): the
    // committed view answers it and the host sees no event.
    // The owner holds the request's exchange and writes the committed
    // result onto it after save and adopt (event-driven admission).
    assert!(admission.join().unwrap()["commits"].is_array());
    let reply = retry.join().unwrap();
    assert_eq!(reply["commits"].as_array().unwrap().len(), 2);
    let joined = call(
        late,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":reply["commits"]}),
    )
    .unwrap();
    assert_eq!(
        call(
            late,
            json!({"op":"adopt_join","snapshot":joined["snapshot"]})
        )
        .unwrap()["members"],
        3
    );
    for handle in [helper, late] {
        close(handle).unwrap();
    }
}

#[test]
fn existing_member_serves_a_later_invitation_after_learning_it_and_restarting() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[221; 32])).unwrap();
    let mut helper = create(Some(&[222; 32])).unwrap();
    let late = create(Some(&[223; 32])).unwrap();
    let workspace = call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator","workspace_name":"Event Team"}),
    )
    .unwrap()["workspace"]
        .clone();
    let first = call(admin, json!({"op":"issue_invitation"})).unwrap();
    let pending = call(
        helper,
        json!({"op":"begin_join","display_name":"Relay member","invitation":first["invitation"],
            "checkpoint":first["checkpoint"]}),
    )
    .unwrap();
    let staged = call(
        admin,
        json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],
            "request":pending["admission_request"]}),
    )
    .unwrap();
    call(
        admin,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap();
    let reply = call(
        admin,
        json!({"op":"retained_admission","authenticated_endpoint":pending["endpoint"],
            "request":pending["admission_request"]}),
    )
    .unwrap();
    let joined = call(
        helper,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":[{
            "commit":reply["commit"],"authorization":reply["authorization"]}]}),
    )
    .unwrap();
    call(
        helper,
        json!({"op":"adopt_join","snapshot":joined["snapshot"]}),
    )
    .unwrap();

    let dir = common::directory();
    let store = dir.path().join("helper.db");
    enable_record_storage(helper, &store, &[222; 32]).unwrap();

    let staged = call(
        admin,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    )
    .unwrap();
    let issued = call(
        admin,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap();
    let invitation = issued["issued_invitation"].clone();
    let admin_node = endpoint(admin);
    call(
        helper,
        json!({"op":"add_address_hint","peer":admin_node["endpoint_key"],
            "address":admin_node["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    call(
        helper,
        json!({"op":"fetch_membership_update","peer":admin_node["endpoint_key"]}),
    )
    .unwrap();
    assert_eq!(serve_once(admin)["state"], "membership_replied");
    let deadline = Instant::now() + Duration::from_secs(10);
    let update = loop {
        let value = call(helper, json!({"op":"poll_membership_update"})).unwrap();
        if value != Value::Null {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "membership update was not received"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(update["state"], "membership_update_available");
    let mut tampered = update["step"].clone();
    let byte = tampered["invitation_checkpoint"]["checkpoint"][0]
        .as_u64()
        .unwrap();
    tampered["invitation_checkpoint"]["checkpoint"][0] = json!(byte ^ 1);
    assert!(
        call(
            helper,
            json!({"op":"stage_admission_update","step":tampered}),
        )
        .is_err()
    );
    assert_eq!(
        call(helper, json!({"op":"member_roster"})).unwrap()["epoch"],
        1
    );
    let learned = call(
        helper,
        json!({"op":"stage_admission_update","step":update["step"]}),
    )
    .unwrap();
    save_candidate(
        helper,
        &serde_json::from_value::<Vec<u8>>(learned["snapshot"].clone()).unwrap(),
    )
    .unwrap();
    call(
        helper,
        json!({"op":"adopt_admission","snapshot":learned["snapshot"]}),
    )
    .unwrap();
    close(admin).unwrap();
    close(helper).unwrap();

    helper = create(Some(&[222; 32])).unwrap();
    restore_record_storage(
        helper,
        &store,
        &[222; 32],
        serde_json::from_value(workspace).unwrap(),
    )
    .unwrap();
    let helper_node = endpoint(helper);
    call(
        late,
        json!({"op":"add_address_hint","peer":helper_node["endpoint_key"],
            "address":helper_node["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    let peer = helper_node["endpoint_key"].clone();
    let bearer = invitation["invitation"].clone();
    let fetch = std::thread::spawn(move || {
        call(
            late,
            json!({"op":"fetch_invitation_checkpoint","peer":peer,"invitation":bearer}),
        )
    });
    // An invitation checkpoint is an inquiry (ADR 0010): the committed view
    // answers it and the host sees no event.
    assert_eq!(
        fetch.join().unwrap().unwrap()["checkpoint"],
        invitation["checkpoint"]
    );

    close(helper).unwrap();
    close(late).unwrap();
    dir.close().unwrap();
}
