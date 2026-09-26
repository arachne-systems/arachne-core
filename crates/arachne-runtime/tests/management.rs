use arachne_runtime::{MemoryProvider, close, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

mod common;

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|e| e.to_string())
}

fn issue(h: i64) -> Value {
    let staged = call(
        h,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    )
    .unwrap();
    call(
        h,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )
    .unwrap()["issued_invitation"]
        .clone()
}

#[test]
fn management_save_adopt_old_invitation_and_removal_over_iroh() {
    let admin = common::stored(&[81; 32], &MemoryProvider::default());
    let helper_provider = MemoryProvider::default();
    let mut helper = common::stored(&[82; 32], &helper_provider);
    let late = common::stored(&[83; 32], &MemoryProvider::default());
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator"}),
    )
    .unwrap();
    let invite = issue(admin);
    let begin = |handle, name| {
        call(
            handle,
            json!({"op":"begin_join",
        "invitation":invite["invitation"],"checkpoint":invite["checkpoint"],"display_name":name}),
        )
        .unwrap()
    };
    let early = begin(helper, "Available member");
    let staged = call(
        admin,
        json!({"op":"stage_admission","authenticated_endpoint":early["endpoint"],
        "request":early["admission_request"]}),
    )
    .unwrap();
    call(
        admin,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )
    .unwrap();
    let reply = call(
        admin,
        json!({"op":"retained_admission","authenticated_endpoint":early["endpoint"],
        "request":early["admission_request"]}),
    )
    .unwrap();
    let staged = call(
        helper,
        json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}),
    )
    .unwrap();
    call(
        helper,
        json!({"op":"adopt_join","candidate":staged["candidate"]}),
    )
    .unwrap();
    close(helper).unwrap();
    helper = common::stored(&[82; 32], &helper_provider);
    call(
        helper,
        json!({"op":"restore_workspace","workspace":invite["workspace"]}),
    )
    .unwrap();
    assert!(
        call(
            helper,
            json!({"op":"stage_invitation","personal":false,"expires_at":0})
        )
        .is_err()
    );
    call(
        helper,
        json!({"op":"add_address_hint","peer":invite["peer"],
        "address":invite["address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    let change = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"promote","member":early["member"]["id"]}}),
    )
    .unwrap();
    assert!(
        change.get("step").is_none(),
        "Do not expose a committable operation before saved adoption"
    );
    assert!(
        call(
            admin,
            json!({"op":"stage_invitation","personal":false,"expires_at":0})
        )
        .is_err()
    );
    assert!(call(admin, json!({"op":"adopt_admission","candidate":[]})).is_err());
    let adopted = call(
        admin,
        json!({"op":"adopt_admission","candidate":change["candidate"]}),
    )
    .unwrap();
    assert_eq!(adopted["step"]["kind"], "promote");
    let step = pull(admin, helper, invite["peer"].clone());
    let roster = call(admin, json!({"op":"member_roster"})).unwrap();
    assert!(
        roster["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["display_name"] == "Available member" && m["administrator"] == true)
    );
    let peer_roster = call(helper, json!({"op":"member_roster"})).unwrap();
    assert!(
        peer_roster["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["display_name"] == "Coordinator")
    );
    let mut damaged = roster["profiles"].clone();
    damaged[0][70] = json!(255);
    let unchanged = call(admin, json!({"op":"member_roster", "profiles":damaged})).unwrap();
    assert_eq!(unchanged["members"], roster["members"]);

    let mut ambiguous = step.clone();
    ambiguous["authorization"] = reply["authorization"].clone();
    assert!(
        call(
            helper,
            json!({"op":"stage_admission_update","step":ambiguous})
        )
        .is_err()
    );
    let change = call(helper, json!({"op":"stage_admission_update","step":step})).unwrap();
    call(
        helper,
        json!({"op":"adopt_admission","candidate":change["candidate"]}),
    )
    .unwrap();
    call(
        helper,
        json!({"op":"fetch_membership_update","peer":invite["peer"]}),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        call(admin, json!({"op":"poll_admission"})).unwrap();
        let current = call(helper, json!({"op":"poll_membership_update"})).unwrap();
        if current != Value::Null {
            assert_eq!(current["state"], "membership_current");
            assert!(
                current.get("profiles").is_none(),
                "equal verified sets need no profile transfer"
            );
            break;
        }
        assert!(Instant::now() < deadline, "Membership profile timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
    let saved_profiles = call(helper, json!({"op":"member_roster"})).unwrap()["profiles"].clone();
    close(helper).unwrap();
    helper = common::stored(&[82; 32], &helper_provider);
    call(
        helper,
        json!({"op":"restore_workspace","workspace":invite["workspace"]}),
    )
    .unwrap();
    call(
        helper,
        json!({"op":"member_roster","profiles":saved_profiles}),
    )
    .unwrap();
    assert!(
        call(
            helper,
            json!({"op":"stage_invitation","personal":false,"expires_at":0})
        )
        .is_ok()
    );
    // Staging only checks authorization here; discard it so it does not sit
    // as an uncommitted candidate blocking the later management ops below.
    call(helper, json!({"op":"discard_workspace_candidate"})).unwrap();
    let node: Value = serde_json::from_str(&describe(helper).unwrap()).unwrap();
    let helper_address = node["bound_address"]
        .as_str()
        .unwrap()
        .replace("0.0.0.0:", "127.0.0.1:");
    call(
        admin,
        json!({"op":"add_address_hint","peer":node["endpoint_key"],"address":helper_address}),
    )
    .unwrap();
    let outsider: Value = serde_json::from_str(&describe(late).unwrap()).unwrap();
    call(
        admin,
        json!({"op":"add_address_hint","peer":outsider["endpoint_key"],"address":"127.0.0.1:9"}),
    )
    .unwrap();
    let routed = issue(admin);
    assert_eq!(
        routed["routes"],
        json!([{"peer":node["endpoint_key"],"address":helper_address}])
    );
    close(admin).unwrap();
    assert!(describe(admin).is_err());
    assert_eq!(
        call(late, json!({"op":"use_service_profile"})).unwrap()["state"],
        "service_profile"
    );
    let late_identity = begin(late, "Late arrival");
    call(
        late,
        json!({"op":"add_address_hint","peer":invite["peer"],
        "address":invite["address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    assert_eq!(
        call(
            late,
            json!({"op":"request_admission","peer":invite["peer"]})
        )
        .unwrap()["state"],
        "admission_not_sent"
    );
    call(
        late,
        json!({"op":"add_address_hint","peer":node["endpoint_key"],
        "address":node["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    )
    .unwrap();
    let helper_peer = node["endpoint_key"].clone();
    let waiting = std::thread::spawn(move || {
        call(
            late,
            json!({"op":"request_admission","peer":node["endpoint_key"]}),
        )
        .unwrap()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let staged = call(helper, json!({"op":"poll_admission"})).unwrap();
        if staged["state"] == "awaiting_save" {
            call(
                helper,
                json!({"op":"adopt_admission","candidate":staged["candidate"]}),
            )
            .unwrap();
            break;
        }
        assert!(
            Instant::now() < deadline,
            "No authenticated admission request"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // The owner holds the request's exchange and writes the committed
    // result onto it after save and adopt (event-driven admission).
    assert!(waiting.join().unwrap()["commits"].is_array());
    let retry_peer = helper_peer.clone();
    let retry = std::thread::spawn(move || {
        call(late, json!({"op":"request_admission","peer":retry_peer})).unwrap()
    });
    // The result is retained, so this retry is an inquiry: the
    // committed view answers it and the host sees no event.
    let reply = retry.join().unwrap();
    let steps = reply.get("commits").expect("complete authorized history");
    assert_eq!(steps.as_array().unwrap().len(), 3);
    assert_eq!(steps[1]["kind"], "promote");
    let mut altered = steps.clone();
    // Byte 39 of a binary step lies in its authorization fields (after
    // `DFMS\x03`, tag, class and a 32-byte key or id).
    altered[0]["step"][39] = json!(steps[0]["step"][39].as_u64().unwrap() ^ 1);
    assert!(
        call(
            late,
            json!({"op":"stage_join","welcome":reply["welcome"],"commits":altered})
        )
        .is_err()
    );
    let staged = call(
        late,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":steps}),
    )
    .expect("reachable member must provide the missing authorized history from the old invitation");
    let joined = call(
        late,
        json!({"op":"adopt_join","candidate":staged["candidate"]}),
    )
    .unwrap();
    assert_eq!(joined["members"], 3);
    // +1: registering the first invitation now costs an epoch before the
    // checkpoint it pins, so the absolute epoch late lands on is one higher.
    assert_eq!(joined["epoch"], 4);
    call(
        late,
        json!({"op":"fetch_membership_update","peer":helper_peer}),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        call(helper, json!({"op":"poll_admission"})).unwrap();
        let current = call(late, json!({"op":"poll_membership_update"})).unwrap();
        if current != Value::Null {
            assert_eq!(current["state"], "membership_current");
            assert_eq!(current["profiles"].as_array().map(Vec::len), Some(2));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Retained member profile timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        call(late, json!({"op":"member_roster"})).unwrap()["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["display_name"] == "Coordinator")
    );
    assert!(
        call(helper, json!({"op":"member_roster"})).unwrap()["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["display_name"] == "Late arrival" && member["kind"] == "service")
    );
    let removal = call(helper, json!({"op":"stage_management","action":{"kind":"remove","member":late_identity["member"]["id"]}})).unwrap();
    call(
        helper,
        json!({"op":"adopt_admission","candidate":removal["candidate"]}),
    )
    .unwrap();
    // Advance again before serving the former member; only its own removal,
    // including its epoch, may be disclosed to it.
    let demotion = call(
        helper,
        json!({"op":"stage_management","action":{"kind":"demote","member":early["member"]["id"]}}),
    )
    .unwrap();
    call(
        helper,
        json!({"op":"adopt_admission","candidate":demotion["candidate"]}),
    )
    .unwrap();
    let removed_step = pull(helper, late, helper_peer);
    assert_eq!(removed_step["kind"], "remove");
    let removed = call(
        late,
        json!({"op":"stage_admission_update","step":removed_step}),
    )
    .unwrap();
    assert_eq!(removed["removed"], true);
    assert!(
        call(
            late,
            json!({"op":"stage_invitation","personal":false,"expires_at":0})
        )
        .is_err()
    );
    assert!(call(late, json!({"op":"adopt_admission","candidate":[]})).is_err());
    let adopted = call(
        late,
        json!({"op":"adopt_admission","candidate":removed["candidate"]}),
    )
    .unwrap();
    assert_eq!(adopted["state"], "removed");
    assert!(describe(late).is_err());
    assert!(call(late, json!({"op":"install_workspace_policy","revision":5})).is_err());
    close(late).unwrap();
    close(helper).unwrap();
}

// Both endpoints remain real Iroh nodes. Polling is test scheduling, not a policy
// injection: the responder checks the authenticated endpoint and public history.
fn pull(responder: i64, receiver: i64, peer: Value) -> Value {
    call(
        receiver,
        json!({"op":"fetch_membership_update","peer":peer}),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        call(responder, json!({"op":"poll_admission"})).unwrap();
        let value = call(receiver, json!({"op":"poll_membership_update"})).unwrap();
        if value != Value::Null {
            assert_eq!(value["state"], "membership_update_available");
            if value["step"]["kind"] == "remove" {
                assert_eq!(
                    value["epoch"].as_u64().unwrap(),
                    value["after"].as_u64().unwrap() + 1
                );
            }
            return value["step"].clone();
        }
        assert!(Instant::now() < deadline, "Membership update timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// ADR A2 section 7: only administrators admit. A member refuses both a
/// host-staged admission and a joiner's request, with a distinct reason the
/// joiner uses to ask its next member.
#[test]
fn a_member_that_is_not_an_administrator_refuses_admissions() {
    let admin = common::stored(&[84; 32], &MemoryProvider::default());
    let member = common::stored(&[85; 32], &MemoryProvider::default());
    let late = common::stored(&[86; 32], &MemoryProvider::default());
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator"}),
    )
    .unwrap();
    let invite = issue(admin);
    let begin = |handle, name| {
        call(
            handle,
            json!({"op":"begin_join","invitation":invite["invitation"],
                "checkpoint":invite["checkpoint"],"display_name":name}),
        )
        .unwrap()
    };
    let joined = begin(member, "Plain member");
    let staged = call(
        admin,
        json!({"op":"stage_admission","authenticated_endpoint":joined["endpoint"],
            "request":joined["admission_request"]}),
    )
    .unwrap();
    call(
        admin,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )
    .unwrap();
    let reply = call(
        admin,
        json!({"op":"retained_admission","authenticated_endpoint":joined["endpoint"],
            "request":joined["admission_request"]}),
    )
    .unwrap();
    let staged = call(
        member,
        json!({"op":"stage_join","welcome":reply["welcome"],
            "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}),
    )
    .unwrap();
    call(
        member,
        json!({"op":"adopt_join","candidate":staged["candidate"]}),
    )
    .unwrap();

    let asking = begin(late, "Late joiner");
    let refused = execute(
        member,
        &serde_json::to_vec(&json!({"op":"stage_admission",
            "authenticated_endpoint":asking["endpoint"],"request":asking["admission_request"]}))
        .unwrap(),
    )
    .unwrap_err();
    assert!(
        refused.contains("Only an administrator can admit members"),
        "{refused}"
    );

    let info: Value = serde_json::from_str(&describe(member).unwrap()).unwrap();
    let address = info["bound_address"]
        .as_str()
        .unwrap()
        .replace("0.0.0.0:", "127.0.0.1:");
    call(
        late,
        json!({"op":"add_address_hint","peer":info["endpoint_key"],"address":address}),
    )
    .unwrap();
    let peer = info["endpoint_key"].clone();
    let asked = std::thread::spawn(move || {
        call(late, json!({"op":"request_admission","peer":peer})).unwrap()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let served = loop {
        let value = call(member, json!({"op":"poll_admission"})).unwrap();
        if value != Value::Null {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "the member never saw the request"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(served["accepted"], false, "{served}");
    assert_eq!(served["reason"], "administrator_required", "{served}");
    let answer = asked.join().unwrap();
    assert_eq!(answer["state"], "admission_unavailable", "{answer}");
    assert_eq!(answer["reason"], "administrator_required", "{answer}");
    for handle in [admin, member, late] {
        close(handle).unwrap();
    }
}
