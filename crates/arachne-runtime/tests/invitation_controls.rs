use arachne_runtime::{MemoryProvider, close, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

mod common;

fn call(h: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(h, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|e| e.to_string())
}
/// A session with its own in-memory record storage.
fn session(seed: u8) -> i64 {
    common::stored(&[seed; 32], &MemoryProvider::default())
}
fn adopt(h: i64, staged: &Value) -> Value {
    call(
        h,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )
    .unwrap()
}
fn apply(h: i64, step: &Value) {
    let staged = call(h, json!({"op":"stage_admission_update","step":step})).unwrap();
    adopt(h, &staged);
}
fn begin(h: i64, invite: &Value) -> Value {
    call(h, json!({"op":"begin_join","display_name":"Attendee","invitation":invite["invitation"],"checkpoint":invite["checkpoint"]})).unwrap()
}

#[test]
fn overlapping_open_admissions_queue_while_membership_commit_is_pending() {
    let admin = session(121);
    let people: Vec<_> = (122..=124)
        .map(session)
        .collect();
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Incident lead","workspace_name":"Wildfire response"}),
    )
    .unwrap();
    let staged = call(
        admin,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    )
    .unwrap();
    let invite = adopt(admin, &staged)["issued_invitation"].clone();
    let admin_info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
    let admin_address = admin_info["bound_address"]
        .as_str()
        .unwrap()
        .replace("0.0.0.0:", "127.0.0.1:");
    let pending: Vec<_> = people.iter().map(|person| begin(*person, &invite)).collect();
    let admin_peer = admin_info["endpoint_key"].clone();
    for (person, request) in people.iter().zip(&pending) {
        call(
            *person,
            json!({"op":"add_address_hint","peer":admin_peer.clone(),"address":admin_address}),
        )
        .unwrap();
        assert_eq!(request["personal_invitation"], false);
    }

    let first_person = people[0];
    let first_peer = admin_peer.clone();
    let first = std::thread::spawn(move || {
        call(
            first_person,
            json!({"op":"request_admission","peer":first_peer}),
        )
        .unwrap()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let first_staged = loop {
        let value = call(admin, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "awaiting_save" {
            break value;
        }
        assert!(Instant::now() < deadline, "first admission was not staged");
        std::thread::sleep(Duration::from_millis(5));
    };

    let queued_waiters: Vec<_> = people[1..]
        .iter()
        .map(|person| {
            let person = *person;
            let peer = admin_info["endpoint_key"].clone();
            std::thread::spawn(move || {
                call(person, json!({"op":"request_admission","peer":peer})).unwrap()
            })
        })
        .collect();
    // While the first membership commit is pending, every later open
    // admission is queued on the owner (counted host-side) and none is
    // committed early. Their exchanges are held, not answered, until their
    // own batch commits (event-driven admission).
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut queued = 0usize;
    while queued < queued_waiters.len() {
        let value = call(admin, json!({"op":"poll_admission"})).unwrap();
        assert!(
            value.is_null() || value["state"] == "admission_queued",
            "unexpected busy admission result: {value}"
        );
        queued += usize::from(value["state"] == "admission_queued");
        assert!(Instant::now() < deadline, "later admissions were not queued promptly");
        std::thread::sleep(Duration::from_millis(5));
    }

    adopt(admin, &first_staged);
    assert!(first.join().unwrap()["commits"].is_array());
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut held_batches = Vec::new();
    while queued_waiters.iter().any(|waiter| !waiter.is_finished()) {
        let value = call(admin, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "awaiting_save" {
            held_batches.push(value["admissions"].as_u64().unwrap());
            adopt(admin, &value);
        }
        assert!(Instant::now() < deadline, "held admissions were not delivered");
        std::thread::sleep(Duration::from_millis(5));
    }
    for waiter in queued_waiters {
        assert!(waiter.join().unwrap()["commits"].is_array());
    }
    let retries: Vec<_> = people
        .iter()
        .map(|person| {
            let person = *person;
            let peer = admin_info["endpoint_key"].clone();
            std::thread::spawn(move || {
                for _ in 0..200 {
                    let reply = call(person, json!({"op":"request_admission","peer":peer})).unwrap();
                    if reply.get("welcome").is_some() {
                        return reply;
                    }
                    assert_eq!(reply, json!({"state":"admission_queued"}));
                    std::thread::sleep(Duration::from_millis(5));
                }
                panic!("admission reply was not retained");
            })
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut staged_admissions = Vec::new();
    while retries.iter().any(|retry| !retry.is_finished()) {
        let value = call(admin, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "awaiting_save" {
            staged_admissions.push(value["admissions"].as_u64().unwrap());
            adopt(admin, &value);
        } else {
            assert!(
                value.is_null()
                    || value["state"] == "admission_replied"
                    || value["state"] == "admission_queued",
                "unexpected concurrent admission result: {value}"
            );
        }
        assert!(Instant::now() < deadline, "concurrent admissions did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
    // With held exchanges the two queued admissions commit together before
    // the retries; either phase may show the batch of two.
    assert!(
        held_batches.contains(&2) || staged_admissions.contains(&2),
        "queued admissions were not batched: held {held_batches:?}, retried {staged_admissions:?}"
    );
    let replies: Vec<_> = retries.into_iter().map(|retry| retry.join().unwrap()).collect();
    assert_eq!(replies[1]["commit"], replies[2]["commit"]);
    assert_eq!(replies[1]["epoch"], replies[2]["epoch"]);
    for (person, reply) in people.iter().zip(replies) {
        assert!(reply.get("welcome").is_some());
        let joined = call(
            *person,
            json!({"op":"stage_join","welcome":reply["welcome"],"commits":reply["commits"]}),
        )
        .unwrap();
        call(
            *person,
            json!({"op":"adopt_join","candidate":joined["candidate"]}),
        )
        .unwrap();
    }
    assert_eq!(
        call(admin, json!({"op":"member_roster"})).unwrap()["members"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    close(admin).unwrap();
    for person in people {
        close(person).unwrap();
    }
}

#[test]
fn overlapping_manual_approval_is_queued_until_the_owner_is_ready() {
    let admin = session(131);
    let first = session(132);
    let requester = session(133);
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Incident lead","workspace_name":"Wildfire response"}),
    )
    .unwrap();
    let staged = call(
        admin,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    )
    .unwrap();
    let open = adopt(admin, &staged)["issued_invitation"].clone();
    let staged = call(
        admin,
        json!({"op":"stage_invitation","personal":true,"automatic":true,"expires_at":0}),
    )
    .unwrap();
    let request_access = adopt(admin, &staged)["issued_invitation"].clone();
    let info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
    let address = info["bound_address"]
        .as_str()
        .unwrap()
        .replace("0.0.0.0:", "127.0.0.1:");
    let _first_pending = begin(first, &open);
    let waiting = begin(requester, &request_access);
    assert_eq!(
        call(
            admin,
            json!({"op":"stage_admission","authenticated_endpoint":waiting["endpoint"],"request":waiting["admission_request"]}),
        )
        .unwrap_err(),
        arachne_security::INVITATION_AUTOMATIC_APPROVAL_REQUIRED
    );
    for person in [first, requester] {
        call(
            person,
            json!({"op":"add_address_hint","peer":info["endpoint_key"],"address":address}),
        )
        .unwrap();
    }
    let first_peer = info["endpoint_key"].clone();
    let first_call = std::thread::spawn(move || {
        call(first, json!({"op":"request_admission","peer":first_peer})).unwrap()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let first_staged = loop {
        let value = call(admin, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "awaiting_save" {
            break value;
        }
        assert!(Instant::now() < deadline, "ordinary admission was not staged");
        std::thread::sleep(Duration::from_millis(5));
    };

    let requester_peer = info["endpoint_key"].clone();
    let waiting_call = std::thread::spawn(move || {
        call(requester, json!({"op":"request_admission","peer":requester_peer})).unwrap()
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !waiting_call.is_finished() {
        let _ = call(admin, json!({"op":"poll_admission"})).unwrap();
        assert!(Instant::now() < deadline, "manual approval was not queued promptly");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        waiting_call.join().unwrap(),
        json!({"state":"admission_queued"})
    );
    adopt(admin, &first_staged);
    // The owner holds the request's exchange and writes the committed
    // result onto it after save and adopt (event-driven admission).
    assert!(first_call.join().unwrap()["commits"].is_array());

    let deadline = Instant::now() + Duration::from_secs(10);
    let approval = loop {
        let value = call(admin, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "approval_requested" {
            break value;
        }
        assert!(Instant::now() < deadline, "queued manual approval was not surfaced");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(approval["request"], waiting["admission_request"]);
    let listed = call(admin, json!({"op":"list_admission_approvals","limit":1})).unwrap();
    assert_eq!(listed["approvals"].as_array().unwrap().len(), 1);
    assert_eq!(listed["approvals"][0]["request"], waiting["admission_request"]);
    let attempt_id: [u8; 32] = serde_json::from_value(listed["approvals"][0]["attempt_id"].clone()).unwrap();
    assert_eq!(
        call(admin, json!({"op":"acknowledge_admission_approval","attempt_id":attempt_id})).unwrap()["acknowledged"],
        true
    );
    let staged = call(
        admin,
        json!({"op":"stage_invitation_approval","attempt_id":attempt_id,"request":waiting["admission_request"]}),
    )
    .unwrap();
    adopt(admin, &staged);

    let retry_peer = info["endpoint_key"].clone();
    let retry = std::thread::spawn(move || {
        call(requester, json!({"op":"request_admission","peer":retry_peer})).unwrap()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let staged = loop {
        let value = call(admin, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "awaiting_save" {
            break value;
        }
        assert!(Instant::now() < deadline, "approved request was not admitted");
        std::thread::sleep(Duration::from_millis(5));
    };
    adopt(admin, &staged);
    // A retry of an approved, queued attempt is held and receives its
    // committed result after save and adopt (event-driven admission).
    assert!(retry.join().unwrap()["commits"].is_array());
    let retry_peer = info["endpoint_key"].clone();
    let final_retry = std::thread::spawn(move || {
        call(requester, json!({"op":"request_admission","peer":retry_peer})).unwrap()
    });
    // The result is retained, so this retry is an inquiry: the
    // committed view answers it and the host sees no event.
    let reply = final_retry.join().unwrap();
    assert!(reply.get("welcome").is_some());
    let joined = call(
        requester,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":reply["commits"]}),
    )
    .unwrap();
    call(
        requester,
        json!({"op":"adopt_join","candidate":joined["candidate"]}),
    )
    .unwrap();
    assert_eq!(
        call(admin, json!({"op":"member_roster"})).unwrap()["members"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    close(admin).unwrap();
    close(first).unwrap();
    close(requester).unwrap();
}

#[test]
fn approved_personal_join_survives_restart_and_uses_peer_while_admin_is_closed() {
    let admin_storage = MemoryProvider::default();
    let admin = common::stored(&[91; 32], &admin_storage);
    let helper = session(92);
    let person_storage = MemoryProvider::default();
    let mut person = common::stored(&[93; 32], &person_storage);
    let copied = session(94);
    let workspace = call(
        admin,
        json!({"op":"create_workspace","display_name":"Organizer","workspace_name":"Field team"}),
    )
    .unwrap()["workspace"]
        .clone();
    let staged = call(
        admin,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    )
    .unwrap();
    assert!(staged.get("issued_invitation").is_none());
    // Adoption saves the exact staged candidate: a changed token is refused.
    let mut altered: Vec<u8> = serde_json::from_value(staged["candidate"].clone()).unwrap();
    altered[36] ^= 1;
    assert!(
        call(
            admin,
            json!({"op":"adopt_admission","candidate":altered})
        )
        .is_err()
    );
    let open = adopt(admin, &staged)["issued_invitation"].clone();
    let early = begin(helper, &open);
    let staged = call(admin, json!({"op":"stage_admission","authenticated_endpoint":early["endpoint"],"request":early["admission_request"]})).unwrap();
    adopt(admin, &staged);
    let reply = call(admin, json!({"op":"retained_admission","authenticated_endpoint":early["endpoint"],"request":early["admission_request"]})).unwrap();
    let staged = call(helper, json!({"op":"stage_join","welcome":reply["welcome"],"commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]})).unwrap();
    call(
        helper,
        json!({"op":"adopt_join","candidate":staged["candidate"]}),
    )
    .unwrap();
    // Native history discovery runs in the background after reconnecting.
    // It must not prevent the administrator from creating the next invitation.
    let peer: Value = serde_json::from_str(&describe(helper).unwrap()).unwrap();
    call(admin, json!({"op":"install_workspace_policy","revision":3})).unwrap();
    let discovery = call(admin, json!({"op":"discover_recovery_cutoff","peer":peer["endpoint_key"],"revision":3,"topics":["chat/messages/v1"]})).unwrap();
    assert_eq!(discovery["state"], "recovery_cutoff_pending");
    let staged = call(
        admin,
        json!({"op":"stage_invitation","personal":true,"automatic":true,"expires_at":0}),
    )
    .unwrap();
    let issued = adopt(admin, &staged);
    assert_eq!(
        call(admin, json!({"op":"poll_recovery_cutoff"})).unwrap(),
        Value::Null
    );
    apply(helper, &issued["step"]);
    let invite = &issued["issued_invitation"];
    let inspection = call(
        copied,
        json!({"op":"inspect_invitation","invitation":invite["invitation"],"checkpoint":invite["checkpoint"]}),
    )
    .unwrap();
    assert_eq!(inspection["automatic_approval"], true);
    // Link details must refer to the identity verified from the issued token,
    // even if another administrator issues an invitation at the same time.
    assert_eq!(invite["invitation_key"].as_array().unwrap().len(), 32);
    assert_eq!(invite["invitation_key"], inspection["invitation_key"]);
    assert_ne!(invite["invitation_key"], open["invitation_key"]);
    let pending = begin(person, invite);
    assert_eq!(pending["personal_invitation"], true);
    let wrong = begin(copied, invite);
    assert!(call(helper, json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],"request":pending["admission_request"]})).is_err());
    assert!(
        call(
            helper,
            json!({"op":"stage_invitation_approval","request":pending["admission_request"]})
        )
        .is_err()
    );
    // A premature retry gets useful feedback without disrupting the member
    // accepting requests. It cannot become membership or consume the request.
    let node: Value = serde_json::from_str(&describe(helper).unwrap()).unwrap();
    call(person, json!({"op":"add_address_hint","peer":node["endpoint_key"],"address":node["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")})).unwrap();
    let waiting = std::thread::spawn(move || {
        call(
            person,
            json!({"op":"request_admission","peer":node["endpoint_key"]}),
        )
    });
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        let response = call(helper, json!({"op":"poll_admission"})).unwrap();
        if response["state"] == "approval_requested" {
            assert_eq!(response["state"], "approval_requested");
            assert_eq!(response["endpoint"], pending["endpoint"]);
            assert_eq!(response["request"], pending["admission_request"]);
            assert_eq!(response["display_name"], "Attendee");
            assert_eq!(response["automatic"], true);
            break;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(10));
    }
    let denied = waiting.join().unwrap().unwrap();
    assert_eq!(
        denied,
        json!({"state":"admission_queued"})
    );
    assert_eq!(
        call(helper, json!({"op":"member_roster"})).unwrap()["members"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // begin_join saved the pending join; a restart restores it from storage.
    assert_eq!(pending["durable"], true);
    close(person).unwrap();
    person = common::stored(&[93; 32], &person_storage);
    let restored = call(
        person,
        json!({"op":"restore_workspace","workspace":workspace.clone()}),
    )
    .unwrap();
    assert_eq!(restored["admission_request"], pending["admission_request"]);
    assert_eq!(restored["personal_invitation"], true);
    let staged = call(
        admin,
        json!({"op":"stage_invitation_approval","request":pending["admission_request"]}),
    )
    .unwrap();
    let approved = adopt(admin, &staged);
    apply(helper, &approved["step"]);
    assert!(call(helper, json!({"op":"stage_admission","authenticated_endpoint":wrong["endpoint"],"request":wrong["admission_request"]})).is_err());
    close(admin).unwrap();
    let helper_node: Value = serde_json::from_str(&describe(helper).unwrap()).unwrap();
    call(person, json!({"op":"add_address_hint","peer":helper_node["endpoint_key"],"address":helper_node["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")})).unwrap();
    let helper_peer = helper_node["endpoint_key"].clone();
    let waiting = std::thread::spawn(move || {
        call(
            person,
            json!({"op":"request_admission","peer":helper_peer}),
        )
    });
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        let staged = call(helper, json!({"op":"poll_admission"})).unwrap();
        if staged["state"] == "awaiting_save" {
            adopt(helper, &staged);
            break;
        }
        assert!(Instant::now() < until, "No approved personal join request");
        std::thread::sleep(Duration::from_millis(10));
    }
    // A retry of an approved, queued attempt is held and receives its
    // committed result after save and adopt (event-driven admission).
    assert!(waiting.join().unwrap().unwrap()["commits"].is_array());
    let helper_peer = helper_node["endpoint_key"].clone();
    let final_retry = std::thread::spawn(move || {
        call(person, json!({"op":"request_admission","peer":helper_peer})).unwrap()
    });
    // The result is retained, so this retry is an inquiry: the
    // committed view answers it and the host sees no event.
    let reply = final_retry.join().unwrap();
    let staged = call(
        person,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":reply["commits"]}),
    )
    .unwrap();
    assert_eq!(
        call(
            person,
            json!({"op":"adopt_join","candidate":staged["candidate"]})
        )
        .unwrap()["members"],
        3
    );
    close(person).unwrap();
    close(helper).unwrap();
    close(copied).unwrap();
    let admin = common::stored(&[91; 32], &admin_storage);
    call(admin, json!({"op":"restore_workspace","workspace":workspace})).unwrap();
    assert_eq!(
        call(admin, json!({"op":"invitation_controls"})).unwrap()["invitations"][1]["approved"],
        true
    );
    close(admin).unwrap();
}

#[test]
fn declining_a_personal_request_disables_its_invitation_without_admitting_it() {
    let admin = session(101);
    let person = session(102);
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Organizer","workspace_name":"Field team"}),
    )
    .unwrap();
    let staged = call(
        admin,
        json!({"op":"stage_invitation","personal":true,"expires_at":0}),
    )
    .unwrap();
    let invite = adopt(admin, &staged)["issued_invitation"].clone();
    let pending = begin(person, &invite);
    let declined = call(
        admin,
        json!({"op":"stage_invitation_decline","request":pending["admission_request"]}),
    )
    .unwrap();
    adopt(admin, &declined);
    assert_eq!(
        call(admin, json!({"op":"invitation_controls"})).unwrap()["invitations"][0]["enabled"],
        false
    );
    assert_eq!(
        call(
            admin,
            json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],"request":pending["admission_request"]}),
        )
        .unwrap_err(),
        arachne_security::INVITATION_DISABLED
    );
    assert_eq!(
        call(admin, json!({"op":"member_roster"})).unwrap()["members"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    close(admin).unwrap();
    close(person).unwrap();
}

#[test]
fn reusable_request_access_keeps_native_commands_and_catalog_scoped() {
    let admin = session(151);
    let people: Vec<_> = (152..=154)
        .map(session)
        .collect();
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Organizer","workspace_name":"Team"}),
    )
    .unwrap();
    let staged = call(
        admin,
        json!({"op":"stage_invitation","personal":true,"request_access":true,"expires_at":0}),
    )
    .unwrap();
    let issued = adopt(admin, &staged);
    let pending: Vec<_> = people
        .iter()
        .map(|h| begin(*h, &issued["issued_invitation"]))
        .collect();
    for (index, request) in pending.iter().enumerate() {
        let op = if index == 1 {
            "stage_invitation_decline"
        } else {
            "stage_invitation_approval"
        };
        let decision = call(
            admin,
            json!({"op":op,"request":request["admission_request"]}),
        )
        .unwrap();
        adopt(admin, &decision);
    }
    let catalog = call(admin, json!({"op":"invitation_controls"})).unwrap();
    assert_eq!(catalog["invitations"].as_array().unwrap().len(), 1);
    assert_eq!(catalog["invitations"][0]["request_access"], true);
    assert_eq!(catalog["invitations"][0]["approved"], false);
    for (index, request) in pending.iter().enumerate() {
        let admission = call(
            admin,
            json!({"op":"stage_admission","authenticated_endpoint":request["endpoint"],"request":request["admission_request"]}),
        );
        if index == 1 {
            assert_eq!(admission.unwrap_err(), arachne_security::INVITATION_DISABLED);
        } else {
            adopt(admin, &admission.unwrap());
        }
    }
    assert_eq!(
        call(admin, json!({"op":"member_roster"})).unwrap()["members"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    close(admin).unwrap();
    for person in people {
        close(person).unwrap();
    }
}
