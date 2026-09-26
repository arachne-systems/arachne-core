use arachne_runtime::{MemoryProvider, close, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

mod common;
fn call(h: i64, v: Value) -> Value {
    serde_json::from_slice(
        &execute(h, &serde_json::to_vec(&v).unwrap())
            .unwrap_or_else(|error| panic!("handle={h}, request={v}: {error}")),
    )
    .unwrap()
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
/// An admission reply's step in the binary step codec.
fn binary_step(reply: &Value) -> Vec<u8> {
    let bytes = |value: &Value| serde_json::from_value::<Vec<u8>>(value.clone()).unwrap();
    let auth = &reply["authorization"];
    arachne_security::encode_membership_step(
        &arachne_security::MembershipAuthorization::Admission(
            arachne_security::AdmissionAuthorization {
                invitation_key: bytes(&auth["invitation_key"]).try_into().unwrap(),
                grant_signature: bytes(&auth["grant_signature"]).try_into().unwrap(),
                redemption_signature: bytes(&auth["redemption_signature"]).try_into().unwrap(),
            },
        ),
        &bytes(&reply["commit"]),
    )
    .unwrap()
}
fn issue(admin: i64) -> Value {
    let staged = call(
        admin,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    );
    call(
        admin,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )["issued_invitation"]
        .clone()
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
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
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
        json!({"op":"adopt_join","candidate":staged["candidate"]}),
    );
    reply
}
#[test]
fn newer_member_offers_verified_history_to_returning_admin_without_helper() {
    let admin_storage = MemoryProvider::default();
    let admin = common::stored(&[71; 32], &admin_storage);
    let helper = common::stored(&[72; 32], &MemoryProvider::default());
    let newer = common::stored(&[73; 32], &MemoryProvider::default());
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Admin"}),
    );
    let invite = issue(admin);
    let first = add(admin, helper, &invite, vec![], "Helper");
    // Only administrators admit (ADR A2): the helper admits while the admin
    // is away, so the admin promotes it first and the helper applies that.
    let roster = call(admin, json!({"op":"member_roster"}));
    let helper_id = roster["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["self"] == false)
        .unwrap()["id"]
        .clone();
    let promotion = call(
        admin,
        json!({"op":"stage_management","action":{"kind":"promote","member":helper_id}}),
    );
    let promoted = call(
        admin,
        json!({"op":"adopt_admission","candidate":promotion["candidate"]}),
    );
    let promote_step = promoted["step"].clone();
    let applied = call(
        helper,
        json!({"op":"stage_admission_update","step":promote_step}),
    );
    call(
        helper,
        json!({"op":"adopt_admission","candidate":applied["candidate"]}),
    );
    close(admin).unwrap();
    let second = add(
        helper,
        newer,
        &invite,
        vec![step(&first), promote_step],
        "New member",
    );
    close(helper).unwrap();
    let admin = common::stored(&[71; 32], &admin_storage);
    call(
        admin,
        json!({"op":"restore_workspace","workspace":invite["workspace"]}),
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
    let mut altered = binary_step(&second);
    // Byte 39 is the first grant signature byte of a binary admission step.
    altered[39] ^= 1;
    let mut packet = b"DFMO\x02".to_vec();
    packet.extend(
        invite["workspace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8),
    );
    // Epoch 3: the link registration, the helper's admission and its
    // promotion come first.
    packet.extend(3u64.to_be_bytes());
    packet.extend(arachne_runtime::harness::wire_step(&altered));
    let peer: [u8; 32] = info["endpoint_key"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let mut valid = packet[..45].to_vec();
    valid.extend(arachne_runtime::harness::wire_step(&binary_step(&second)));
    let mut wrong_workspace = valid.clone();
    wrong_workspace[5] ^= 1;
    let mut wrong_epoch = valid.clone();
    wrong_epoch[44] = 9;
    let mut wrong_version = valid.clone();
    wrong_version[4] = 1;
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
                &json!({"op":"offer_membership_update","peer":([99;32]),"after":3})
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
        json!({"op":"offer_membership_update","peer":info["endpoint_key"],"after":3}),
    );
    let candidate = poll(admin, "poll_admission");
    assert_eq!(candidate["state"], "awaiting_save");
    assert!(call(newer, json!({"op":"poll_membership_offer"})).is_null());
    let saved = call(
        admin,
        json!({"op":"adopt_admission","candidate":candidate["candidate"]}),
    );
    assert_eq!(saved["members"], 3);
    assert_eq!(saved["epoch"], 4);
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
        json!({"op":"offer_membership_update","peer":info["endpoint_key"],"after":3}),
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
    let a = common::stored(&[101; 32], &MemoryProvider::default());
    let b_storage = MemoryProvider::default();
    let b = common::stored(&[102; 32], &b_storage);
    let c = common::stored(&[103; 32], &MemoryProvider::default());
    call(a, json!({"op":"create_workspace","display_name":"Admin"}));
    let invite = issue(a);
    let first = add(a, b, &invite, vec![], "Existing member");
    add(a, c, &invite, vec![step(&first)], "New member");
    let info = |h| serde_json::from_str::<Value>(&describe(h).unwrap()).unwrap();
    let address = |v: &Value| {
        v["bound_address"]
            .as_str()
            .unwrap()
            .replace("0.0.0.0:", "127.0.0.1:")
    };
    let ai = info(a);
    let bi = info(b);
    let ci = info(c);
    for (h, peers) in [(a, vec![&bi, &ci]), (b, vec![&ai]), (c, vec![&ai, &bi])] {
        for peer in peers {
            call(
                h,
                json!({"op":"add_address_hint","peer":peer["endpoint_key"],"address":address(peer)}),
            );
        }
    }
    assert_eq!(
        call(b, json!({"op":"member_roster"}))["members"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    call(a, json!({"op":"poll_workspace_presence","announce":true}));
    assert_eq!(poll(b, "poll_admission")["state"], "presence_replied");
    // A newer epoch in a presence reply starts the runtime's range pull;
    // the host is not asked to sync as well.
    let observed = call(b, json!({"op":"poll_workspace_presence"}));
    assert!(observed["sync_peer"].is_null(), "{observed}");
    // An authenticated announcement prompts synchronization but never grants membership.
    let roster = call(b, json!({"op":"member_roster"}));
    assert_eq!(roster["members"].as_array().unwrap().len(), 2);
    assert!(
        roster["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["endpoint"] == ai["endpoint_key"] && m["presence"] == "reachable")
    );
    let end = Instant::now() + Duration::from_secs(10);
    let staged = loop {
        for h in [a, c] {
            call(h, json!({"op":"poll_admission"}));
        }
        let result = call(b, json!({"op":"poll_admission"}));
        if result["state"] == "awaiting_save" {
            break result;
        }
        assert!(
            Instant::now() < end,
            "the range pull did not stage the step: {result}"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    call(
        b,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    );
    close(b).unwrap();
    let b = common::stored(&[102; 32], &b_storage);
    call(
        b,
        json!({"op":"restore_workspace","workspace":invite["workspace"]}),
    );
    let roster = call(b, json!({"op":"member_roster"}));
    assert_eq!(roster["members"].as_array().unwrap().len(), 3);
    assert!(
        roster["members"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["self"] == false)
            .all(|m| m["presence"] == "unknown")
    );
    // Only the returning peer knows a current route. Its valid announcement
    // must refresh the receiver's observed route without any PLI/publication.
    call(
        b,
        json!({"op":"add_address_hint","peer":ai["endpoint_key"],"address":address(&ai)}),
    );
    call(b, json!({"op":"poll_workspace_presence","announce":true}));
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        for h in [a, b, c] {
            call(h, json!({"op":"poll_admission"}));
        }
        call(b, json!({"op":"poll_workspace_presence"}));
        if call(b, json!({"op":"member_roster"}))["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["endpoint"] == ai["endpoint_key"] && m["presence"] == "reachable")
        {
            break;
        }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    call(
        a,
        json!({"op":"fetch_membership_update","peer":bi["endpoint_key"],"replace_pending":true}),
    );
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        for h in [a, b, c] {
            call(h, json!({"op":"poll_admission"}));
        }
        let result = call(a, json!({"op":"poll_membership_update"}));
        if !result.is_null() {
            assert_eq!(result["state"], "membership_current");
            break;
        }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    let peer: [u8; 32] = serde_json::from_value(ai["endpoint_key"].clone()).unwrap();
    let dest = address(&ai).parse().unwrap();
    let workspace: [u8; 32] = serde_json::from_value(invite["workspace"].clone()).unwrap();
    let outsider = std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (node, _) = arachne_node::Node::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            node.add_address_hint(peer, dest).await.unwrap();
            let mut forged = b"DFPR\x01".to_vec();
            forged.extend(workspace);
            forged.extend([0; 40]);
            assert_eq!(node.request_control(peer, &forged).await.unwrap(), [0]);
            node.close().await;
        })
    });
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let result = call(a, json!({"op":"poll_admission"}));
        if result["state"] == "presence_replied" && result["accepted"] == false {
            break;
        }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    outsider.join().unwrap();
    assert_eq!(
        call(a, json!({"op":"member_roster"}))["members"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    for h in [a, b, c] {
        close(h).unwrap();
    }
}

#[test]
fn simultaneous_presence_and_self_updates_converge_and_survive_restart() {
    let stores: [MemoryProvider; 3] = std::array::from_fn(|_| MemoryProvider::default());
    let nodes: [i64; 3] = std::array::from_fn(|i| common::stored(&[151 + i as u8; 32], &stores[i]));
    let [admin, existing, newer] = nodes;
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Admin"}),
    );
    let invite = issue(admin);
    let first = add(admin, existing, &invite, vec![], "Existing");
    add(admin, newer, &invite, vec![step(&first)], "Newer");
    assert_eq!(
        call(existing, json!({"op":"member_roster"}))["members"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    for &from in &nodes {
        for &to in &nodes {
            if from == to {
                continue;
            }
            let info: Value = serde_json::from_str(&describe(to).unwrap()).unwrap();
            call(
                from,
                json!({"op":"add_address_hint","peer":info["endpoint_key"],
                "address":info["bound_address"].as_str().unwrap().replace("0.0.0.0:", "127.0.0.1:")}),
            );
        }
        call(
            from,
            json!({"op":"poll_workspace_presence","announce":true}),
        );
    }

    let admin_info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut self_updated = [false; 3];
    let mut events = Vec::new();
    let expected = loop {
        for (index, &node) in nodes.iter().enumerate() {
            call(node, json!({"op":"poll_workspace_presence"}));
            let value = call(node, json!({"op":"drive_workspace"}));
            if value["state"] == "self_update_committed" {
                self_updated[index] = true;
            }
            if let Some(state) = value["state"].as_str() {
                events.push((index, state.to_owned(), value["epoch"].clone()));
            }
        }
        let rosters = nodes.map(|node| call(node, json!({"op":"member_roster"})));
        if self_updated[1..].iter().all(|updated| *updated)
            && rosters
                .iter()
                .all(|roster| roster["members"].as_array().unwrap().len() == 3)
            && rosters
                .iter()
                .all(|roster| roster["epoch"] == rosters[0]["epoch"])
        {
            // Equal heights can still hold different self-update branches.
            // Let the driver finish fork recovery before calling this converged.
            let mut authority_matches = true;
            for (index, peer) in [(1, existing), (2, newer)] {
                call(
                    peer,
                    json!({"op":"fetch_membership_update","peer":admin_info["endpoint_key"],"replace_pending":true}),
                );
                let agreed = loop {
                    let value = call(peer, json!({"op":"poll_membership_update"}));
                    if !value.is_null() {
                        break value;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "membership agreement stalled: events={events:?}"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                };
                let state = agreed["state"].as_str().unwrap();
                assert!(
                    matches!(state, "membership_current" | "membership_branch_mismatch"),
                    "{agreed}"
                );
                authority_matches &= state == "membership_current";
                events.push((index, state.to_owned(), agreed["epoch"].clone()));
            }
            if authority_matches {
                break rosters[0]["epoch"].clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "three-member sync stalled: rosters={rosters:?}; events={events:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    // Equal epoch numbers alone do not prove equal membership authority.
    // A current reply verifies the peer's epoch fingerprint against ours.
    for peer in [existing, newer] {
        call(
            peer,
            json!({"op":"fetch_membership_update","peer":admin_info["endpoint_key"],"replace_pending":true}),
        );
        let agreed = poll(peer, "poll_membership_update");
        assert_eq!(agreed["state"], "membership_current", "{agreed}");
    }
    for node in nodes {
        close(node).unwrap();
    }
    for (index, store) in stores.iter().enumerate() {
        let node = common::stored(&[151 + index as u8; 32], store);
        let restored = call(
            node,
            json!({"op":"restore_workspace","workspace":invite["workspace"]}),
        );
        assert_eq!(restored["epoch"], expected);
        assert_eq!(restored["members"], 3);
        close(node).unwrap();
    }
}
