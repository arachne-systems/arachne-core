use arachne_runtime::{close, create, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
fn call(h: i64, v: Value) -> Value {
    serde_json::from_slice(&execute(h, &serde_json::to_vec(&v).unwrap()).unwrap()).unwrap()
}
fn poll(h: i64, op: &str) -> Value {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let v = call(h, json!({"op":op}));
        if !v.is_null() {
            return v;
        }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn step(reply: &Value) -> Value {
    json!({"commit":reply["commit"],"authorization":reply["authorization"]})
}
fn add(owner: i64, joiner: i64, invite: &Value, prior: Vec<Value>, name: &str) -> Value {
    let begin = call(
        joiner,
        json!({"op":"begin_join","invitation":invite["invitation"],"checkpoint":invite["checkpoint"],"display_name":name}),
    );
    let staged = call(
        owner,
        json!({"op":"stage_admission","authenticated_endpoint":begin["endpoint"],"request":begin["admission_request"]}),
    );
    call(
        owner,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    );
    let reply = call(
        owner,
        json!({"op":"retained_admission","authenticated_endpoint":begin["endpoint"],"request":begin["admission_request"]}),
    );
    let mut steps = prior;
    steps.push(step(&reply));
    let staged = call(
        joiner,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":steps}),
    );
    call(
        joiner,
        json!({"op":"adopt_join","snapshot":staged["snapshot"]}),
    );
    reply
}
#[test]
fn newer_member_offers_verified_history_to_returning_admin_without_helper() {
    let admin = create(Some(&[71; 32])).unwrap();
    let helper = create(Some(&[72; 32])).unwrap();
    let newer = create(Some(&[73; 32])).unwrap();
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Admin"}),
    );
    let invite = call(admin, json!({"op":"issue_invitation"}));
    let first = add(admin, helper, &invite, vec![], "Helper");
    let saved = call(admin, json!({"op":"seal_workspace"}));
    close(admin).unwrap();
    let second = add(helper, newer, &invite, vec![step(&first)], "New member");
    close(helper).unwrap();
    let admin = create(Some(&[71; 32])).unwrap();
    call(
        admin,
        json!({"op":"restore_workspace","workspace":invite["workspace"],"snapshot":saved["snapshot"]}),
    );
    let info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
    let address = info["bound_address"]
        .as_str()
        .unwrap()
        .replace("0.0.0.0:", "127.0.0.1:");
    call(
        newer,
        json!({"op":"add_address_hint","peer":info["endpoint_key"],"address":address}),
    );
    let before = call(admin, json!({"op":"member_roster"}));
    assert_eq!(before["members"].as_array().unwrap().len(), 2);
    call(
        newer,
        json!({"op":"fetch_membership_update","peer":info["endpoint_key"]}),
    );
    assert_eq!(poll(admin, "poll_admission")["state"], "membership_replied");
    assert_eq!(
        poll(newer, "poll_membership_update")["state"],
        "membership_denied"
    );
    // A transport-authenticated outsider's corrupted offer must not mutate membership.
    let mut altered = step(&second);
    altered["authorization"]["grant_signature"][0] = json!(
        altered["authorization"]["grant_signature"][0]
            .as_u64()
            .unwrap()
            ^ 1
    );
    let mut packet = b"DFMO\x01".to_vec();
    packet.extend(
        invite["workspace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8),
    );
    packet.extend(1u64.to_be_bytes());
    packet.extend(serde_json::to_vec(&altered).unwrap());
    let peer: [u8; 32] = info["endpoint_key"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let mut valid = packet[..45].to_vec();
    valid.extend(serde_json::to_vec(&step(&second)).unwrap());
    let mut wrong_workspace = valid.clone();
    wrong_workspace[5] ^= 1;
    let mut wrong_epoch = valid.clone();
    wrong_epoch[44] = 9;
    let mut wrong_version = valid.clone();
    wrong_version[4] = 2;
    let packets = vec![
        packet,
        wrong_workspace,
        wrong_epoch,
        wrong_version,
        valid[..44].to_vec(),
    ];
    let rejected_count = packets.len();
    assert!(
        execute(
            newer,
            &serde_json::to_vec(
                &json!({"op":"offer_membership_update","peer":([99;32]),"after":1})
            )
            .unwrap()
        )
        .is_err()
    );
    let outsider = std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (node, _) = arachne_node::Node::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            node.add_address_hint(peer, address.parse().unwrap())
                .await
                .unwrap();
            for packet in packets {
                assert_eq!(node.request_control(peer, &packet).await.unwrap(), [0]);
            }
            node.close().await;
        })
    });
    for _ in 0..rejected_count {
        assert_eq!(poll(admin, "poll_admission")["state"], "membership_replied");
        assert_eq!(call(admin, json!({"op":"member_roster"})), before);
    }
    outsider.join().unwrap();
    call(
        newer,
        json!({"op":"offer_membership_update","peer":info["endpoint_key"],"after":1}),
    );
    let candidate = poll(admin, "poll_admission");
    assert_eq!(candidate["state"], "awaiting_save");
    assert!(call(newer, json!({"op":"poll_membership_offer"})).is_null());
    let saved = call(
        admin,
        json!({"op":"adopt_admission","snapshot":candidate["snapshot"]}),
    );
    assert_eq!(saved["members"], 3);
    assert_eq!(saved["epoch"], 2);
    assert_eq!(
        call(admin, json!({"op":"send_admission_reply"}))["queued"],
        true
    );
    assert_eq!(
        poll(newer, "poll_membership_offer")["state"],
        "membership_offer_finished"
    );
    // Replayed transition receives only a generic rejection, never duplicate membership.
    call(
        newer,
        json!({"op":"offer_membership_update","peer":info["endpoint_key"],"after":1}),
    );
    assert_eq!(poll(admin, "poll_admission")["state"], "membership_replied");
    poll(newer, "poll_membership_offer");
    assert_eq!(
        call(admin, json!({"op":"member_roster"}))["members"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    close(admin).unwrap();
    close(newer).unwrap();
}

#[test]
fn group_presence_announces_new_members_and_returning_peers_without_application_topics() {
    let a = create(Some(&[101; 32])).unwrap();
    let b = create(Some(&[102; 32])).unwrap();
    let c = create(Some(&[103; 32])).unwrap();
    call(a, json!({"op":"create_workspace","display_name":"Admin"}));
    let invite = call(a, json!({"op":"issue_invitation"}));
    let first = add(a, b, &invite, vec![], "Existing member");
    add(a, c, &invite, vec![step(&first)], "New member");
    let info = |h| serde_json::from_str::<Value>(&describe(h).unwrap()).unwrap();
    let address = |v: &Value| v["bound_address"].as_str().unwrap().replace("0.0.0.0:", "127.0.0.1:");
    let ai = info(a);
    let bi = info(b);
    let ci = info(c);
    for (h, peers) in [(a, vec![&bi, &ci]), (b, vec![&ai]), (c, vec![&ai, &bi])] {
        for peer in peers { call(h, json!({"op":"add_address_hint","peer":peer["endpoint_key"],"address":address(peer)})); }
    }
    assert_eq!(call(b, json!({"op":"member_roster"}))["members"].as_array().unwrap().len(), 2);
    call(a, json!({"op":"poll_workspace_presence","announce":true}));
    assert_eq!(poll(b, "poll_admission")["state"], "presence_replied");
    // A newer epoch in a presence reply starts the runtime's range pull
    // (ADR 0009); the host is not asked to sync as well.
    let observed = call(b, json!({"op":"poll_workspace_presence"}));
    assert!(observed["sync_peer"].is_null(), "{observed}");
    // An authenticated announcement prompts synchronization but never grants membership.
    let roster = call(b, json!({"op":"member_roster"}));
    assert_eq!(roster["members"].as_array().unwrap().len(), 2);
    assert!(roster["members"].as_array().unwrap().iter().any(|m| m["endpoint"] == ai["endpoint_key"] && m["presence"] == "reachable"));
    let end = Instant::now() + Duration::from_secs(10);
    let staged = loop {
        for h in [a,c] { call(h, json!({"op":"poll_admission"})); }
        let result = call(b, json!({"op":"poll_admission"}));
        if result["state"] == "awaiting_save" { break result; }
        assert!(Instant::now() < end, "the range pull did not stage the step: {result}");
        std::thread::sleep(Duration::from_millis(5));
    };
    call(b, json!({"op":"adopt_admission","snapshot":staged["snapshot"]}));
    let saved = call(b, json!({"op":"seal_workspace"}));
    close(b).unwrap();
    let b = create(Some(&[102;32])).unwrap();
    call(b, json!({"op":"restore_workspace","workspace":invite["workspace"],"snapshot":saved["snapshot"]}));
    let roster = call(b, json!({"op":"member_roster"}));
    assert_eq!(roster["members"].as_array().unwrap().len(), 3);
    assert!(roster["members"].as_array().unwrap().iter().filter(|m| m["self"] == false).all(|m| m["presence"] == "unknown"));
    // Only the returning peer knows a current route. Its valid announcement
    // must refresh the receiver's observed route without any PLI/publication.
    call(b, json!({"op":"add_address_hint","peer":ai["endpoint_key"],"address":address(&ai)}));
    call(b, json!({"op":"poll_workspace_presence","announce":true}));
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        for h in [a,b,c] { call(h, json!({"op":"poll_admission"})); }
        call(b, json!({"op":"poll_workspace_presence"}));
        if call(b, json!({"op":"member_roster"}))["members"].as_array().unwrap().iter().any(|m| m["endpoint"] == ai["endpoint_key"] && m["presence"] == "reachable") { break; }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    call(a, json!({"op":"fetch_membership_update","peer":bi["endpoint_key"],"replace_pending":true}));
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        for h in [a,b,c] { call(h, json!({"op":"poll_admission"})); }
        let result = call(a, json!({"op":"poll_membership_update"}));
        if !result.is_null() { assert_eq!(result["state"], "membership_current"); break; }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    let peer: [u8;32] = serde_json::from_value(ai["endpoint_key"].clone()).unwrap();
    let dest = address(&ai).parse().unwrap();
    let workspace: [u8;32] = serde_json::from_value(invite["workspace"].clone()).unwrap();
    let outsider = std::thread::spawn(move || tokio::runtime::Runtime::new().unwrap().block_on(async {
        let (node, _) = arachne_node::Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        node.add_address_hint(peer, dest).await.unwrap();
        let mut forged = b"DFPR\x01".to_vec(); forged.extend(workspace); forged.extend([0;40]);
        assert_eq!(node.request_control(peer, &forged).await.unwrap(), [0]);
        node.close().await;
    }));
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let result = call(a, json!({"op":"poll_admission"}));
        if result["state"] == "presence_replied" && result["accepted"] == false { break; }
        assert!(Instant::now() < end); std::thread::sleep(Duration::from_millis(5));
    }
    outsider.join().unwrap();
    assert_eq!(call(a, json!({"op":"member_roster"}))["members"].as_array().unwrap().len(), 3);
    for h in [a,b,c] { close(h).unwrap(); }
}
