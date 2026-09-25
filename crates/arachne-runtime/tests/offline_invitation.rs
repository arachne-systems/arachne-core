use arachne_runtime::{close, create, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

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
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap()
}

#[test]
fn old_invitation_redeems_through_an_ordinary_member_with_issuer_closed() {
    let admin = create(Some(&[81; 32])).unwrap();
    let mut helper = create(Some(&[82; 32])).unwrap();
    let late = create(Some(&[83; 32])).unwrap();
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator"}),
    )
    .unwrap();
    let invite = issue_invitation(admin)["issued_invitation"].clone();
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
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
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
        json!({"op":"adopt_join","snapshot":staged["snapshot"]}),
    )
    .unwrap();
    close(helper).unwrap();
    helper = create(Some(&[82; 32])).unwrap();
    call(helper, json!({"op":"restore_workspace","workspace":invite["workspace"],"snapshot":staged["snapshot"]})).unwrap();
    assert!(call(helper, json!({"op":"stage_invitation","personal":false,"expires_at":0})).is_err());
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
    let adopted = issue_invitation(admin);
    // helper is already a member at this point, so it must apply the
    // registration step too or it forks from admin's view.
    let s = call(
        helper,
        json!({"op":"stage_admission_update","step":adopted["step"]}),
    )
    .unwrap();
    call(
        helper,
        json!({"op":"adopt_admission","snapshot":s["snapshot"]}),
    )
    .unwrap();
    let routed = adopted["issued_invitation"].clone();
    assert_eq!(
        routed["routes"],
        json!([{"peer":node["endpoint_key"],"address":helper_address}])
    );
    assert_eq!(routed["bootstrap_peers"].as_array().unwrap().len(), 2);
    assert_eq!(routed["bootstrap_peers"][0], routed["peer"]);
    assert!(
        routed["bootstrap_peers"]
            .as_array()
            .unwrap()
            .contains(&node["endpoint_key"])
    );
    close(admin).unwrap();
    assert!(describe(admin).is_err());
    begin(late, "Late arrival");
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
    let retry_node = node.clone();
    let waiting = std::thread::spawn(move || {
        call(
            late,
            json!({"op":"request_admission","peer":node["endpoint_key"]}),
        )
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let staged = call(helper, json!({"op":"poll_admission"})).unwrap();
        if staged["state"] == "awaiting_save" {
            call(
                helper,
                json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
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
    assert!(waiting.join().unwrap().unwrap()["commits"].is_array());
    let retry = std::thread::spawn(move || {
        call(
            late,
            json!({"op":"request_admission","peer":retry_node["endpoint_key"]}),
        )
        .unwrap()
    });
    // The result is retained, so this retry is an inquiry: the
    // committed view answers it and the host sees no event.
    let reply = retry.join().unwrap();
    let steps = reply.get("commits").expect("complete authorized history");
    // 2 -> 3: registering both invitations now costs an epoch each, and the
    // invite1 checkpoint is captured after its own registration, so the
    // extra step here is only the "routed" invitation's registration commit
    // that helper had to apply.
    assert_eq!(steps.as_array().unwrap().len(), 3);
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
    assert!(call(late, json!({"op":"seal_pending_join"})).is_ok());
    let staged = call(
        late,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":steps}),
    )
    .expect("reachable member must provide the missing authorized history from the old invitation");
    let joined = call(
        late,
        json!({"op":"adopt_join","snapshot":staged["snapshot"]}),
    )
    .unwrap();
    assert_eq!(joined["members"], 3);
    // 2 -> 4: +2 epochs from registering both invitations (invite1 before
    // helper joined, "routed" after).
    assert_eq!(joined["epoch"], 4);
    close(late).unwrap();
    close(helper).unwrap();
}
