use arachne_runtime::{MemoryProvider, close, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

mod common;

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|error| error.to_string())
}

/// A session with its own in-memory record storage.
fn session(seed: u8) -> i64 {
    common::stored(&[seed; 32], &MemoryProvider::default())
}

fn endpoint(handle: i64) -> Value {
    serde_json::from_str(&describe(handle).unwrap()).unwrap()
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
    let admin = session(201);
    let joiner = session(202);
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator","workspace_name":"Ridge Team"}),
    )
    .unwrap();
    let invitation = issue_invitation(admin);
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
    // An invitation checkpoint is an inquiry: the committed view
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
        json!({"op":"adopt_admission","candidate":renamed["candidate"]}),
    )
    .unwrap();
    let fetch_again = || {
        let peer = admin_node["endpoint_key"].clone();
        let bearer = invitation["invitation"].clone();
        std::thread::spawn(move || {
            call(
                joiner,
                json!({"op":"fetch_invitation_checkpoint","peer":peer,"invitation":bearer}),
            )
        })
        .join()
        .unwrap()
    };
    // A registered link keeps its retained checkpoint across later changes.
    assert_eq!(
        fetch_again().unwrap()["checkpoint"],
        invitation["checkpoint"]
    );
    // Once the link is disabled its checkpoint is gone and becomes stale.
    let disabled = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"disable_invitation",
            "member":invitation["invitation_key"]}}),
    )
    .unwrap();
    call(
        admin,
        json!({"op":"adopt_admission","candidate":disabled["candidate"]}),
    )
    .unwrap();
    assert!(fetch_again().is_err());

    let outsider = session(203);
    let outsider_node = endpoint(outsider);
    let requester = session(204);
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
    let admin = session(211);
    let helper_storage = MemoryProvider::default();
    let mut helper = common::stored(&[212; 32], &helper_storage);
    let late = session(213);
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator","workspace_name":"Event Team"}),
    )
    .unwrap();
    let invitation = issue_invitation(admin);
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
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
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
        json!({"op":"adopt_join","candidate":joined["candidate"]}),
    )
    .unwrap();
    close(admin).unwrap();
    close(helper).unwrap();
    helper = common::stored(&[212; 32], &helper_storage);
    call(
        helper,
        json!({"op":"restore_workspace","workspace":invitation["workspace"]}),
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
    // An invitation checkpoint is an inquiry: the committed view
    // answers it and the host sees no event.
    let fetched = fetch.join().unwrap().unwrap();
    assert_eq!(fetched["checkpoint"], invitation["checkpoint"]);
    call(
        late,
        json!({"op":"begin_join","display_name":"Late member","invitation":invitation["invitation"],
            "checkpoint":fetched["checkpoint"]}),
    )
    .unwrap();
    // Only administrators admit (ADR A2): the ordinary member serves the
    // checkpoint, but refuses the admission itself so the joiner asks an
    // administrator.
    let peer = helper_node["endpoint_key"].clone();
    let admission = std::thread::spawn(move || {
        call(late, json!({"op":"request_admission","peer":peer})).unwrap()
    });
    let served = serve_once(helper);
    assert_eq!(served["reason"], "administrator_required", "{served}");
    let refused = admission.join().unwrap();
    assert_eq!(refused["state"], "admission_unavailable", "{refused}");
    assert_eq!(refused["reason"], "administrator_required", "{refused}");
    for handle in [helper, late] {
        close(handle).unwrap();
    }
}

#[test]
fn existing_member_serves_a_later_invitation_after_learning_it_and_restarting() {
    let admin = session(221);
    let helper_storage = MemoryProvider::default();
    let mut helper = common::stored(&[222; 32], &helper_storage);
    let late = session(223);
    let workspace = call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator","workspace_name":"Event Team"}),
    )
    .unwrap()["workspace"]
        .clone();
    let first = issue_invitation(admin);
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
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
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
        json!({"op":"adopt_join","candidate":joined["candidate"]}),
    )
    .unwrap();

    let staged = call(
        admin,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    )
    .unwrap();
    let issued = call(
        admin,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
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
    // +1: registering the first invitation now costs an epoch before the
    // admission that seated helper, so helper's epoch here is one higher.
    assert_eq!(
        call(helper, json!({"op":"member_roster"})).unwrap()["epoch"],
        2
    );
    let learned = call(
        helper,
        json!({"op":"stage_admission_update","step":update["step"]}),
    )
    .unwrap();
    call(
        helper,
        json!({"op":"adopt_admission","candidate":learned["candidate"]}),
    )
    .unwrap();
    close(admin).unwrap();
    close(helper).unwrap();

    helper = common::stored(&[222; 32], &helper_storage);
    call(
        helper,
        json!({"op":"restore_workspace","workspace":workspace}),
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
    // An invitation checkpoint is an inquiry: the committed view
    // answers it and the host sees no event.
    assert_eq!(
        fetch.join().unwrap().unwrap()["checkpoint"],
        invitation["checkpoint"]
    );

    close(helper).unwrap();
    close(late).unwrap();
}
