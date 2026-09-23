use arachne_runtime::{close, create, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Three four-node scenarios exceed the process-wide runtime budget if overlapped.
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const EVENT: &str = "atak/native/v1/chat";
const CURRENT: &str = "atak/native/v1/pli";

fn call(handle: i64, request: Value) -> Value {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap())
        .unwrap()
}

fn close_for_impairment(handle: i64) {
    if let Err(error) = close(handle) {
        assert_eq!(error, "node shutdown timed out");
    }
    assert!(describe(handle).is_err());
}

fn step(reply: &Value) -> Value {
    json!({"commit":reply["commit"],"authorization":reply["authorization"]})
}

fn add(owner: i64, joiner: i64, invite: &Value, prior: Vec<Value>, name: &str) -> Value {
    let begin = call(
        joiner,
        json!({"op":"begin_join","invitation":invite["invitation"],
            "checkpoint":invite["checkpoint"],"display_name":name}),
    );
    let staged = call(
        owner,
        json!({"op":"stage_admission","authenticated_endpoint":begin["endpoint"],
            "request":begin["admission_request"]}),
    );
    call(
        owner,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    );
    let reply = call(
        owner,
        json!({"op":"retained_admission","authenticated_endpoint":begin["endpoint"],
            "request":begin["admission_request"]}),
    );
    let mut commits = prior;
    commits.push(step(&reply));
    let staged = call(
        joiner,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":commits}),
    );
    call(
        joiner,
        json!({"op":"adopt_join","snapshot":staged["snapshot"]}),
    );
    let mut reply = reply;
    reply["joined_member"] = begin["member"]["id"].clone();
    reply
}

fn connect(from: i64, to: i64) {
    let info: Value = serde_json::from_str(&describe(to).unwrap()).unwrap();
    call(
        from,
        json!({"op":"add_address_hint","peer":info["endpoint_key"],
            "address":info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    );
}

fn finish_range(servers: &[i64], client: i64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        for server in servers {
            let served = call(*server, json!({"op":"poll_admission"}));
            if !served.is_null() {
                assert_eq!(served["state"], "recovery_replied");
            }
        }
        let result = call(client, json!({"op":"poll_recovery_range"}));
        if !result.is_null() {
            return result;
        }
        assert!(Instant::now() < deadline, "recovery did not complete");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn finish_current(servers: &[i64], client: i64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        for server in servers {
            let served = call(*server, json!({"op":"poll_admission"}));
            if !served.is_null() {
                assert_eq!(served["state"], "current_view_replied");
            }
        }
        let result = call(client, json!({"op":"poll_current_view"}));
        if !result.is_null() {
            return result;
        }
        assert!(Instant::now() < deadline, "current view did not complete");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn receive_one(handle: i64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let staged = call(handle, json!({"op":"poll_protected"}));
        if !staged.is_null() {
            call(
                handle,
                json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
            );
            return staged;
        }
        assert!(Instant::now() < deadline, "publication was not received");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn retained_replay_delivers_events_current_values_and_deletions() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let author = create(Some(&[121; 32])).unwrap();
    let reader = create(Some(&[122; 32])).unwrap();
    call(
        author,
        json!({"op":"create_workspace","display_name":"Author"}),
    );
    let invite = call(author, json!({"op":"issue_invitation"}));
    add(author, reader, &invite, vec![], "Reader");
    for handle in [author, reader] {
        let staged = call(handle, json!({"op":"enable_object_delivery"}));
        call(
            handle,
            json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
        );
        call(
            handle,
            json!({"op":"install_workspace_policy","revision":2}),
        );
    }
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    for (id, topic, tombstone) in [(1, EVENT, false), (2, CURRENT, false), (3, CURRENT, true)] {
        let mut request = json!({"op":"stage_network_publication","revision":2,
            "topic":topic,"id":vec![id;16],"payload":[id]});
        if topic == CURRENT {
            request["current"] = json!({"selector":vec![8;32],"replacement_key":vec![9;32],
                "expires_at":expires_at,"tombstone":tombstone});
        }
        let staged = call(author, request);
        call(
            author,
            json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
        );
    }
    connect(reader, author);
    let info: Value = serde_json::from_str(&describe(author).unwrap()).unwrap();
    let query = json!({"op":"fetch_recovery_range","peer":info["endpoint_key"],
        "revision":2,"topics":[EVENT,CURRENT],"after":0,"through":3});
    call(reader, query.clone());
    assert_eq!(finish_range(&[author], reader)["packet_count"], 3);
    let staged = call(reader, json!({"op":"stage_recovery_range"}));
    assert_eq!(
        staged["publication_count"], 3,
        "Current envelopes were silently skipped"
    );
    call(
        reader,
        json!({"op":"adopt_recovery","snapshot":staged["snapshot"]}),
    );
    for id in 1..=3 {
        let pending = call(reader, json!({"op":"poll_pending_object"}));
        assert_eq!(pending["id"], json!(vec![id; 16]));
        assert_eq!(pending["payload"], json!([id]));
        if id != 1 {
            assert_eq!(pending["current"]["expires_at"], expires_at);
            assert_eq!(pending["current"]["tombstone"], id == 3);
        }
        let ack = call(
            reader,
            json!({"op":"stage_object_acknowledgement",
            "member":pending["member"],"topic":pending["topic"],
            "counter":pending["counter"],"id":pending["id"]}),
        );
        call(
            reader,
            json!({"op":"adopt_reception","snapshot":ack["snapshot"]}),
        );
    }
    assert!(call(reader, json!({"op":"poll_pending_object"})).is_null());
    call(reader, query);
    finish_range(&[author], reader);
    assert_eq!(
        call(reader, json!({"op":"stage_recovery_range"}))["state"],
        "recovery_no_new_objects"
    );
    close(reader).unwrap();
    close(author).unwrap();
}

#[test]
fn expired_current_in_group_recovery_is_not_pending() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let author = create(Some(&[91; 32])).unwrap();
    let reader = create(Some(&[92; 32])).unwrap();
    let created = call(
        author,
        json!({"op":"create_workspace","display_name":"Author"}),
    );
    let invite = call(author, json!({"op":"issue_invitation"}));
    add(author, reader, &invite, vec![], "Reader");
    for handle in [author, reader] {
        let staged = call(handle, json!({"op":"enable_object_delivery"}));
        call(
            handle,
            json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
        );
        call(
            handle,
            json!({"op":"install_workspace_policy","revision":2}),
        );
    }
    for (id, topic) in [(1, EVENT), (2, CURRENT), (3, EVENT)] {
        let mut request = json!({"op":"stage_network_publication","revision":2,
            "topic":topic,"id":vec![id;16],"payload":[id]});
        if topic == CURRENT {
            request["current"] = json!({"selector":vec![8;32],
                "replacement_key":vec![9;32],"expires_at":1});
        }
        let staged = call(author, request);
        call(
            author,
            json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
        );
    }
    connect(reader, author);
    for topic in [EVENT, CURRENT] {
        call(
            reader,
            json!({"op":"subscribe","workspace":created["workspace"],
                "revision":2,"topic":topic}),
        );
    }
    let info: Value = serde_json::from_str(&describe(author).unwrap()).unwrap();
    let member = call(author, json!({"op":"member_roster"}))["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["self"] == true)
        .unwrap()["id"]
        .clone();
    call(
        reader,
        json!({"op":"fetch_recovery_range","peer":info["endpoint_key"],
            "author":member,"revision":2,"topics":[EVENT,CURRENT],"after":0,"through":3}),
    );
    assert_eq!(finish_range(&[author], reader)["packet_count"], 3);
    let staged = call(reader, json!({"op":"stage_recovery_range"}));
    call(
        reader,
        json!({"op":"adopt_recovery","snapshot":staged["snapshot"]}),
    );
    assert!(
        call(
            reader,
            json!({"op":"next_group_gap","author":member,"topics":[EVENT]}),
        )
        .is_null()
    );
    for id in [1, 3] {
        let pending = call(reader, json!({"op":"poll_pending_object"}));
        assert_eq!(pending["id"], json!(vec![id; 16]));
        assert_eq!(pending["payload"], json!([id]));
        let ack = call(
            reader,
            json!({"op":"stage_object_acknowledgement",
            "member":pending["member"],"topic":pending["topic"],
            "counter":pending["counter"],"id":pending["id"]}),
        );
        call(
            reader,
            json!({"op":"adopt_reception","snapshot":ack["snapshot"]}),
        );
    }
    assert!(
        call(reader, json!({"op":"poll_pending_object"})).is_null(),
        "expired current state was delivered to the application"
    );
    close(author).unwrap();
    close(reader).unwrap();
}

#[test]
fn expired_live_current_is_not_pending_and_queued_values_expire() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let author = create(Some(&[93; 32])).unwrap();
    let reader = create(Some(&[94; 32])).unwrap();
    let created = call(
        author,
        json!({"op":"create_workspace","display_name":"Author"}),
    );
    let invite = call(author, json!({"op":"issue_invitation"}));
    add(author, reader, &invite, vec![], "Reader");
    for handle in [author, reader] {
        let staged = call(handle, json!({"op":"enable_object_delivery"}));
        call(
            handle,
            json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
        );
        call(
            handle,
            json!({"op":"install_workspace_policy","revision":2}),
        );
    }
    connect(reader, author);
    connect(author, reader);
    let report = call(
        reader,
        json!({"op":"subscribe","workspace":created["workspace"],
            "revision":2,"topic":CURRENT}),
    );
    assert!(
        report["admitted"]
            .as_array()
            .is_some_and(|peers| !peers.is_empty())
    );
    let staged = call(
        author,
        json!({"op":"stage_network_publication","revision":2,
            "topic":CURRENT,"id":vec![93;16],"payload":[93],
            "current":{"selector":vec![8;32],"replacement_key":vec![9;32],
                "expires_at":1}}),
    );
    call(
        author,
        json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
    );
    assert_eq!(receive_one(reader)["state"], "awaiting_reception_save");
    assert!(
        call(reader, json!({"op":"poll_pending_object"})).is_null(),
        "expired live current state was delivered to the application"
    );
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    let staged = call(
        author,
        json!({"op":"stage_network_publication","revision":2,
            "topic":CURRENT,"id":vec![95;16],"payload":[95],
            "current":{"selector":vec![8;32],"replacement_key":vec![9;32],
                "expires_at":expires_at}}),
    );
    call(
        author,
        json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
    );
    assert_eq!(receive_one(reader)["state"], "awaiting_reception_save");
    assert_eq!(
        call(reader, json!({"op":"poll_pending_object"}))["payload"],
        json!([95])
    );
    let deadline = Instant::now() + Duration::from_secs(4);
    while SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        < expires_at
    {
        assert!(
            Instant::now() < deadline,
            "current value did not expire in time"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        call(reader, json!({"op":"poll_pending_object"})).is_null(),
        "current state expired while queued but was still delivered"
    );
    close(reader).unwrap();
    close(author).unwrap();
}

#[test]
fn newest_tombstone_beats_stale_holder_and_survives_reader_restart() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let author = create(Some(&[111; 32])).unwrap();
    let stale_holder = create(Some(&[112; 32])).unwrap();
    let fresh_holder = create(Some(&[113; 32])).unwrap();
    let reader = create(Some(&[114; 32])).unwrap();
    let created = call(
        author,
        json!({"op":"create_workspace","display_name":"Author"}),
    );
    let invite = call(author, json!({"op":"issue_invitation"}));
    let stale = add(author, stale_holder, &invite, vec![], "Stale holder");
    let fresh = add(
        author,
        fresh_holder,
        &invite,
        vec![step(&stale)],
        "Fresh holder",
    );
    let joined = add(
        author,
        reader,
        &invite,
        vec![step(&stale), step(&fresh)],
        "Reader",
    );
    for (handle, updates) in [
        (stale_holder, vec![step(&fresh), step(&joined)]),
        (fresh_holder, vec![step(&joined)]),
    ] {
        for update in updates {
            let staged = call(handle, json!({"op":"stage_admission_update","step":update}));
            call(
                handle,
                json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
            );
        }
    }
    for handle in [author, stale_holder, fresh_holder, reader] {
        let staged = call(handle, json!({"op":"enable_object_delivery"}));
        call(
            handle,
            json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
        );
        call(
            handle,
            json!({"op":"install_workspace_policy","revision":4}),
        );
    }
    connect(stale_holder, author);
    connect(fresh_holder, author);
    let author_info: Value = serde_json::from_str(&describe(author).unwrap()).unwrap();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let selector = vec![8; 32];
    let replacement_key = vec![9; 32];

    let event = call(
        author,
        json!({"op":"stage_network_publication","revision":4,
            "topic":EVENT,"id":vec![1;16],"payload":[42]}),
    );
    call(
        author,
        json!({"op":"adopt_publication","snapshot":event["snapshot"]}),
    );
    let created_state = call(
        author,
        json!({"op":"stage_network_publication","revision":4,
            "topic":CURRENT,"id":vec![2;16],"payload":[1],
            "current":{"selector":selector.clone(),"replacement_key":replacement_key.clone(),
                "expires_at":expires_at}}),
    );
    call(
        author,
        json!({"op":"adopt_publication","snapshot":created_state["snapshot"]}),
    );

    call(
        stale_holder,
        json!({"op":"fetch_recovery_range","peer":author_info["endpoint_key"],
            "revision":4,"topics":[EVENT],"after":0,"through":1}),
    );
    assert_eq!(finish_range(&[author], stale_holder)["packet_count"], 1);
    let retained = call(
        stale_holder,
        json!({"op":"stage_recovery_range","retain_until":expires_at}),
    );
    call(
        stale_holder,
        json!({"op":"adopt_recovery","snapshot":retained["snapshot"]}),
    );
    call(
        stale_holder,
        json!({"op":"fetch_current_view","peer":author_info["endpoint_key"],
            "authority":created["member"]["id"],"revision":4,
            "topic":CURRENT,"selector":selector.clone()}),
    );
    assert_eq!(finish_current(&[author], stale_holder)["cut"], 1);
    let retained = call(stale_holder, json!({"op":"stage_current_view"}));
    call(
        stale_holder,
        json!({"op":"adopt_current_view","snapshot":retained["snapshot"]}),
    );

    for (id, payload, tombstone) in [([3; 16], vec![2], false), ([4; 16], vec![0], true)] {
        let staged = call(
            author,
            json!({"op":"stage_network_publication","revision":4,
                "topic":CURRENT,"id":id,"payload":payload,
                "current":{"selector":selector.clone(),"replacement_key":replacement_key.clone(),
                    "expires_at":expires_at,"tombstone":tombstone}}),
        );
        call(
            author,
            json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
        );
    }
    call(
        fresh_holder,
        json!({"op":"fetch_current_view","peer":author_info["endpoint_key"],
            "authority":created["member"]["id"],"revision":4,
            "topic":CURRENT,"selector":selector.clone()}),
    );
    assert_eq!(finish_current(&[author], fresh_holder)["cut"], 3);
    let retained = call(fresh_holder, json!({"op":"stage_current_view"}));
    call(
        fresh_holder,
        json!({"op":"adopt_current_view","snapshot":retained["snapshot"]}),
    );
    close(author).unwrap();

    connect(reader, stale_holder);
    connect(reader, fresh_holder);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let pending = call(
            reader,
            json!({"op":"fetch_current_view","authority":created["member"]["id"],
                "revision":4,"topic":CURRENT,"selector":selector.clone()}),
        );
        if pending["state"] == "current_view_pending" && pending["candidate_count"] == 2 {
            break;
        }
        if pending["state"] == "current_view_pending" {
            // Overlay neighbors arrive independently. Drain an early one-holder
            // probe without adopting it, then test the required two-holder merge.
            assert_eq!(pending["candidate_count"], 1);
            finish_current(&[stale_holder, fresh_holder], reader);
            call(reader, json!({"op":"cancel_current_view"}));
        } else {
            assert_eq!(pending["state"], "current_view_source_waiting");
        }
        assert!(
            Instant::now() < deadline,
            "both holders did not become reachable"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let ready = finish_current(&[stale_holder, fresh_holder], reader);
    assert_eq!(ready["cut"], 3);
    assert_eq!(ready["attempted"], 2);
    let staged = call(reader, json!({"op":"stage_current_view"}));
    call(
        reader,
        json!({"op":"adopt_current_view","snapshot":staged["snapshot"]}),
    );
    let deleted = call(reader, json!({"op":"poll_pending_object"}));
    assert_eq!(deleted["payload"], json!([0]));
    assert_eq!(deleted["current"]["tombstone"], true);
    let acknowledged = call(
        reader,
        json!({"op":"stage_object_acknowledgement","member":deleted["member"],
            "topic":deleted["topic"],"counter":deleted["counter"],"id":deleted["id"]}),
    );
    call(
        reader,
        json!({"op":"adopt_reception","snapshot":acknowledged["snapshot"]}),
    );
    let saved_reader = call(reader, json!({"op":"seal_workspace"}));
    close(reader).unwrap();

    let reader = create(Some(&[114; 32])).unwrap();
    call(
        reader,
        json!({"op":"restore_workspace","workspace":created["workspace"],
            "snapshot":saved_reader["snapshot"]}),
    );
    call(
        reader,
        json!({"op":"install_workspace_policy","revision":4}),
    );
    connect(reader, stale_holder);
    let stale_info: Value = serde_json::from_str(&describe(stale_holder).unwrap()).unwrap();
    call(
        reader,
        json!({"op":"fetch_current_view","peer":stale_info["endpoint_key"],
            "authority":created["member"]["id"],"revision":4,
            "topic":CURRENT,"selector":selector.clone()}),
    );
    assert_eq!(finish_current(&[stale_holder], reader)["cut"], 1);
    let error = execute(
        reader,
        &serde_json::to_vec(&json!({"op":"stage_current_view"})).unwrap(),
    )
    .unwrap_err();
    assert!(error.contains("current-view rollback"));
    call(reader, json!({"op":"cancel_current_view"}));
    assert!(call(reader, json!({"op":"poll_pending_object"})).is_null());

    call(
        reader,
        json!({"op":"fetch_recovery_range","peer":stale_info["endpoint_key"],
            "author":created["member"]["id"],"revision":4,
            "topics":[EVENT],"after":0,"through":1}),
    );
    assert_eq!(finish_range(&[stale_holder], reader)["packet_count"], 1);
    let recovered = call(reader, json!({"op":"stage_recovery_range"}));
    call(
        reader,
        json!({"op":"adopt_recovery","snapshot":recovered["snapshot"]}),
    );
    assert_eq!(
        call(reader, json!({"op":"poll_pending_object"}))["payload"],
        json!([42])
    );

    close(stale_holder).unwrap();
    close(fresh_holder).unwrap();
    close(reader).unwrap();
}

#[test]
fn intended_recipient_recovers_private_tail_from_restarted_holder() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let author = create(Some(&[101; 32])).unwrap();
    let holder = create(Some(&[102; 32])).unwrap();
    let reader = create(Some(&[103; 32])).unwrap();
    let observer = create(Some(&[104; 32])).unwrap();
    let created = call(
        author,
        json!({"op":"create_workspace","display_name":"Author"}),
    );
    let invite = call(author, json!({"op":"issue_invitation"}));
    let first = add(author, holder, &invite, vec![], "Holder");
    let second = add(author, reader, &invite, vec![step(&first)], "Reader");
    let third = add(
        author,
        observer,
        &invite,
        vec![step(&first), step(&second)],
        "Observer",
    );
    let staged = call(
        holder,
        json!({"op":"stage_admission_update","step":step(&second)}),
    );
    call(
        holder,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    );
    for handle in [holder, reader] {
        let staged = call(
            handle,
            json!({"op":"stage_admission_update","step":step(&third)}),
        );
        call(
            handle,
            json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
        );
    }
    for handle in [author, holder, reader, observer] {
        let staged = call(handle, json!({"op":"enable_object_delivery"}));
        call(
            handle,
            json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
        );
        call(
            handle,
            json!({"op":"install_workspace_policy","revision":4}),
        );
    }
    for (from, to) in [
        (author, holder),
        (holder, author),
        (author, reader),
        (reader, author),
    ] {
        connect(from, to);
    }
    for handle in [holder, reader, observer] {
        call(
            handle,
            json!({"op":"subscribe","workspace":created["workspace"],
                "revision":4,"topic":EVENT}),
        );
    }
    let saved_reader = call(reader, json!({"op":"seal_workspace"}));
    close(reader).unwrap();
    let mut recipients = [
        serde_json::from_value::<[u8; 32]>(first["joined_member"].clone()).unwrap(),
        serde_json::from_value::<[u8; 32]>(second["joined_member"].clone()).unwrap(),
    ];
    recipients.sort_unstable();
    let recipients = json!(recipients);
    let staged = call(
        author,
        json!({"op":"stage_network_publication","revision":4,"topic":EVENT,
            "id":vec![1;16],"payload":[1],"recipients":recipients}),
    );
    let sent = call(
        author,
        json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
    );
    assert_eq!(sent["sequence"], 1);
    receive_one(holder);

    let reader = create(Some(&[103; 32])).unwrap();
    call(
        reader,
        json!({"op":"restore_workspace","workspace":created["workspace"],
            "snapshot":saved_reader["snapshot"]}),
    );
    call(
        reader,
        json!({"op":"install_workspace_policy","revision":4}),
    );
    call(
        reader,
        json!({"op":"subscribe","workspace":created["workspace"],
            "revision":4,"topic":EVENT}),
    );
    let saved_holder = call(holder, json!({"op":"seal_workspace"}));
    close(holder).unwrap();
    close(author).unwrap();
    let holder = create(Some(&[102; 32])).unwrap();
    call(
        holder,
        json!({"op":"restore_workspace","workspace":created["workspace"],
            "snapshot":saved_holder["snapshot"]}),
    );
    call(
        holder,
        json!({"op":"install_workspace_policy","revision":4}),
    );
    for (from, to) in [
        (reader, holder),
        (holder, reader),
        (observer, holder),
        (holder, observer),
    ] {
        connect(from, to);
    }
    for handle in [reader, observer] {
        call(
            handle,
            json!({"op":"subscribe","workspace":created["workspace"],
                "revision":4,"topic":EVENT}),
        );
        call(
            handle,
            json!({"op":"poll_workspace_presence","announce":true}),
        );
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let gap = loop {
        for _ in 0..2 {
            let served = call(holder, json!({"op":"poll_admission"}));
            if !served.is_null() {
                assert_eq!(served["state"], "presence_replied");
            }
        }
        call(reader, json!({"op":"poll_workspace_presence"}));
        call(observer, json!({"op":"poll_workspace_presence"}));
        let gap = call(reader, json!({"op":"next_direct_gap"}));
        if !gap.is_null() {
            break gap;
        }
        assert!(Instant::now() < deadline, "private tail was not announced");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(gap["after"], 0);
    assert_eq!(gap["through"], 1);
    assert!(call(observer, json!({"op":"next_direct_gap"})).is_null());
    let pending = call(
        reader,
        json!({"op":"fetch_direct_recovery","author":gap["author"],
            "revision":gap["revision"],"topic":gap["topic"],
            "recipients":gap["recipients"],"after":gap["after"],"through":gap["through"]}),
    );
    assert_eq!(pending["state"], "direct_recovery_pending");
    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = loop {
        let served = call(holder, json!({"op":"poll_admission"}));
        if !served.is_null() {
            // The observer's concurrent presence request may finish after the
            // intended reader has already learned its missing tail.
            assert!(matches!(
                served["state"].as_str(),
                Some("direct_recovery_replied" | "presence_replied")
            ));
        }
        let ready = call(reader, json!({"op":"poll_direct_recovery"}));
        if !ready.is_null() {
            break ready;
        }
        assert!(
            Instant::now() < deadline,
            "direct recovery did not complete"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(ready["state"], "direct_recovery_ready");
    assert_eq!(ready["packet_count"], 1);
    let staged = call(reader, json!({"op":"stage_direct_recovery"}));
    assert_eq!(staged["publication_count"], 1);
    call(
        reader,
        json!({"op":"adopt_recovery","snapshot":staged["snapshot"]}),
    );
    assert!(call(reader, json!({"op":"next_direct_gap"})).is_null());
    assert_eq!(
        call(reader, json!({"op":"poll_pending_object"}))["payload"],
        json!([1])
    );
    close(holder).unwrap();
    close(reader).unwrap();
    close(observer).unwrap();
}

#[test]
fn restarted_holder_repairs_offline_author_and_removal_blocks_recovery() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let author = create(Some(&[91; 32])).unwrap();
    let holder = create(Some(&[92; 32])).unwrap();
    let reader = create(Some(&[93; 32])).unwrap();
    let empty_holder = create(Some(&[94; 32])).unwrap();
    let created = call(
        author,
        json!({"op":"create_workspace","display_name":"Author"}),
    );
    let invite = call(author, json!({"op":"issue_invitation"}));
    let first = add(author, holder, &invite, vec![], "Holder");
    let second = add(author, reader, &invite, vec![step(&first)], "Reader");
    let third = add(
        author,
        empty_holder,
        &invite,
        vec![step(&first), step(&second)],
        "Empty holder",
    );
    let staged = call(
        holder,
        json!({"op":"stage_admission_update","step":step(&second)}),
    );
    call(
        holder,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    );
    for handle in [holder, reader] {
        let staged = call(
            handle,
            json!({"op":"stage_admission_update","step":step(&third)}),
        );
        call(
            handle,
            json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
        );
    }
    for handle in [author, holder, reader, empty_holder] {
        let staged = call(handle, json!({"op":"enable_object_delivery"}));
        call(
            handle,
            json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
        );
        call(
            handle,
            json!({"op":"install_workspace_policy","revision":4}),
        );
    }

    let publication = call(
        author,
        json!({"op":"stage_network_publication","revision":4,
            "topic":EVENT,"id":vec![7;16],"payload":[42]}),
    );
    let publication = call(
        author,
        json!({"op":"adopt_publication","snapshot":publication["snapshot"]}),
    );
    assert_eq!(publication["sequence"], 1);
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let selector = vec![8; 32];
    let current = call(
        author,
        json!({"op":"stage_network_publication","revision":4,
            "topic":CURRENT,"id":vec![8;16],"payload":[43],
            "current":{"selector":selector.clone(),"replacement_key":created["member"]["id"],
                "expires_at":expires_at}}),
    );
    let current = call(
        author,
        json!({"op":"adopt_publication","snapshot":current["snapshot"]}),
    );
    assert_eq!(current["sequence"], 2);
    let holder_member = first["joined_member"].clone();
    let reader_member = second["joined_member"].clone();
    let saved_author = call(author, json!({"op":"seal_workspace"}));

    connect(holder, author);
    let author_info: Value = serde_json::from_str(&describe(author).unwrap()).unwrap();
    call(
        holder,
        json!({"op":"fetch_recovery_range","peer":author_info["endpoint_key"],
            "revision":4,"topics":[EVENT],"after":0,"through":1}),
    );
    assert_eq!(finish_range(&[author], holder)["packet_count"], 1);
    let retain_until = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let retained = call(
        holder,
        json!({"op":"stage_recovery_range","retain_until":retain_until}),
    );
    call(
        holder,
        json!({"op":"adopt_recovery","snapshot":retained["snapshot"]}),
    );
    call(
        holder,
        json!({"op":"fetch_current_view","peer":author_info["endpoint_key"],
            "authority":created["member"]["id"],"revision":4,
            "topic":CURRENT,"selector":selector.clone()}),
    );
    assert_eq!(
        finish_current(&[author], holder)["state"],
        "current_view_ready"
    );
    let retained = call(holder, json!({"op":"stage_current_view"}));
    call(
        holder,
        json!({"op":"adopt_current_view","snapshot":retained["snapshot"]}),
    );
    let saved = call(holder, json!({"op":"seal_workspace"}));
    close(holder).unwrap();
    close(author).unwrap();

    let holder = create(Some(&[92; 32])).unwrap();
    call(
        holder,
        json!({"op":"restore_workspace","workspace":created["workspace"],
            "snapshot":saved["snapshot"]}),
    );
    call(
        holder,
        json!({"op":"install_workspace_policy","revision":4}),
    );
    let waiting = call(
        reader,
        json!({"op":"fetch_recovery_range","author":created["member"]["id"],
            "revision":4,"topics":[EVENT],"after":0,"through":1}),
    );
    assert_eq!(waiting["state"], "recovery_source_waiting");

    connect(reader, empty_holder);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let result = call(
            reader,
            json!({"op":"fetch_recovery_range","author":created["member"]["id"],
                "revision":4,"topics":[EVENT]}),
        );
        if result["state"] == "recovery_range_pending" {
            assert_eq!(result["automatic_source"], true);
            assert_eq!(result["candidate_count"], 1);
            break;
        }
        assert_eq!(result["state"], "recovery_source_waiting");
        assert!(
            Instant::now() < deadline,
            "holder did not enter the Gossip view"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let unavailable = finish_range(&[empty_holder], reader);
    assert_eq!(unavailable["state"], "recovery_source_unavailable");
    assert_eq!(unavailable["attempted"], 1);
    assert_eq!(unavailable["automatic_source"], true);

    close(empty_holder).unwrap();
    connect(reader, holder);
    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = loop {
        let result = call(
            reader,
            json!({"op":"fetch_recovery_range","author":created["member"]["id"],
                "revision":4,"topics":[EVENT]}),
        );
        if result["state"] == "recovery_range_pending" {
            let result = finish_range(&[holder], reader);
            if result["state"] == "recovery_range_ready" {
                break result;
            }
            assert_eq!(result["state"], "recovery_source_unavailable");
        } else {
            assert_eq!(result["state"], "recovery_source_waiting");
        }
        assert!(
            Instant::now() < deadline,
            "valid holder did not enter the Gossip view"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(ready["packet_count"], 1);
    assert_eq!(ready["automatic_source"], true);
    let recovered = call(reader, json!({"op":"stage_recovery_range"}));
    assert_eq!(recovered["publication_count"], 1);
    call(
        reader,
        json!({"op":"adopt_recovery","snapshot":recovered["snapshot"]}),
    );
    let pending = call(reader, json!({"op":"poll_pending_object"}));
    assert_eq!(pending["payload"], json!([42]));
    assert_eq!(pending["member"], created["member"]["id"]);

    call(
        reader,
        json!({"op":"fetch_recovery_range","author":created["member"]["id"],
            "revision":4,"topics":[EVENT],"after":0,"through":1}),
    );
    assert_eq!(
        finish_range(&[holder], reader)["state"],
        "recovery_range_ready"
    );
    assert_eq!(
        call(reader, json!({"op":"stage_recovery_range"}))["state"],
        "recovery_already_covered"
    );
    let saved_reader = call(reader, json!({"op":"seal_workspace"}));
    close(reader).unwrap();

    let reader = create(Some(&[93; 32])).unwrap();
    call(
        reader,
        json!({"op":"restore_workspace","workspace":created["workspace"],
            "snapshot":saved_reader["snapshot"]}),
    );
    call(
        reader,
        json!({"op":"install_workspace_policy","revision":4}),
    );
    connect(reader, holder);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let started = call(
            reader,
            json!({"op":"fetch_recovery_range","author":created["member"]["id"],
                "revision":4,"topics":[EVENT],"after":0,"through":1}),
        );
        if started["state"] == "recovery_range_pending" {
            break;
        }
        assert_eq!(started["state"], "recovery_source_waiting");
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        finish_range(&[holder], reader)["state"],
        "recovery_range_ready"
    );
    assert_eq!(
        call(reader, json!({"op":"stage_recovery_range"}))["state"],
        "recovery_already_covered"
    );

    let pending = call(reader, json!({"op":"poll_pending_object"}));
    let acknowledged = call(
        reader,
        json!({"op":"stage_object_acknowledgement","member":pending["member"],
            "topic":pending["topic"],"counter":pending["counter"],"id":pending["id"]}),
    );
    call(
        reader,
        json!({"op":"adopt_reception","snapshot":acknowledged["snapshot"]}),
    );

    let started = call(
        reader,
        json!({"op":"fetch_current_view","authority":created["member"]["id"],
            "revision":4,"topic":CURRENT,"selector":selector.clone()}),
    );
    assert_eq!(started["state"], "current_view_pending");
    assert_eq!(started["automatic_source"], true);
    let ready = finish_current(&[holder], reader);
    assert_eq!(ready["state"], "current_view_ready");
    assert_eq!(ready["automatic_source"], true);
    let staged = call(reader, json!({"op":"stage_current_view"}));
    assert_eq!(staged["pending"], 1);
    call(
        reader,
        json!({"op":"adopt_current_view","snapshot":staged["snapshot"]}),
    );
    let current = call(reader, json!({"op":"poll_pending_object"}));
    assert_eq!(current["payload"], json!([43]));
    assert_eq!(current["current"]["selector"], json!(selector));
    let acknowledged = call(
        reader,
        json!({"op":"stage_object_acknowledgement","member":current["member"],
            "topic":current["topic"],"counter":current["counter"],"id":current["id"]}),
    );
    call(
        reader,
        json!({"op":"adopt_reception","snapshot":acknowledged["snapshot"]}),
    );

    let author = create(Some(&[91; 32])).unwrap();
    call(
        author,
        json!({"op":"restore_workspace","workspace":created["workspace"],
            "snapshot":saved_author["snapshot"]}),
    );
    let removal = call(
        author,
        json!({"op":"stage_management","action":{"kind":"remove","member":holder_member}}),
    );
    let removal = call(
        author,
        json!({"op":"adopt_admission","snapshot":removal["snapshot"]}),
    );
    let accepted = call(
        reader,
        json!({"op":"stage_admission_update","step":removal["step"]}),
    );
    call(
        reader,
        json!({"op":"adopt_admission","snapshot":accepted["snapshot"]}),
    );
    let enabled = call(reader, json!({"op":"enable_object_delivery"}));
    call(
        reader,
        json!({"op":"adopt_reception","snapshot":enabled["snapshot"]}),
    );
    call(
        reader,
        json!({"op":"install_workspace_policy","revision":5}),
    );
    let reader_info: Value = serde_json::from_str(&describe(reader).unwrap()).unwrap();
    connect(holder, reader);
    call(
        holder,
        json!({"op":"fetch_recovery_range","peer":reader_info["endpoint_key"],
            "author":reader_member,"revision":4,"topics":[EVENT],
            "after":0,"through":1}),
    );
    let denied = finish_range(&[reader], holder);
    assert_eq!(denied["state"], "recovery_range_rejected");
    assert_eq!(denied["reason"], "Denied");

    let removed_endpoint: Value = serde_json::from_str(&describe(holder).unwrap()).unwrap();
    assert_eq!(
        execute(
            reader,
            &serde_json::to_vec(&json!({"op":"fetch_recovery_range",
                "peer":removed_endpoint["endpoint_key"],"revision":5,
                "topics":[EVENT],"after":0,"through":1}))
            .unwrap(),
        )
        .unwrap_err(),
        "recovery peer is not a current member"
    );
    let saved_reader = call(reader, json!({"op":"seal_workspace"}));
    close(reader).unwrap();
    let reader = create(Some(&[93; 32])).unwrap();
    call(
        reader,
        json!({"op":"restore_workspace","workspace":created["workspace"],
            "snapshot":saved_reader["snapshot"]}),
    );
    call(
        reader,
        json!({"op":"install_workspace_policy","revision":5}),
    );
    assert_eq!(
        execute(
            reader,
            &serde_json::to_vec(&json!({"op":"fetch_recovery_range",
                "peer":removed_endpoint["endpoint_key"],"revision":5,
                "topics":[EVENT],"after":0,"through":1}))
            .unwrap(),
        )
        .unwrap_err(),
        "recovery peer is not a current member"
    );

    close(author).unwrap();
    close(holder).unwrap();
    close(reader).unwrap();
}

#[test]
fn group_tail_recovers_from_a_retained_three_client_holder() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let author = create(Some(&[131; 32])).unwrap();
    let holder = create(Some(&[132; 32])).unwrap();
    let reader = create(Some(&[133; 32])).unwrap();
    let created = call(
        author,
        json!({"op":"create_workspace","display_name":"Author"}),
    );
    let invite = call(author, json!({"op":"issue_invitation"}));
    let holder_join = add(author, holder, &invite, vec![], "Holder");
    let reader_join = add(author, reader, &invite, vec![step(&holder_join)], "Reader");
    let staged = call(
        holder,
        json!({"op":"stage_admission_update","step":step(&reader_join)}),
    );
    call(
        holder,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    );
    let revision = 3;
    for handle in [author, holder, reader] {
        let staged = call(handle, json!({"op":"enable_object_delivery"}));
        call(
            handle,
            json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
        );
        call(
            handle,
            json!({"op":"install_workspace_policy","revision":revision}),
        );
    }
    for (from, to) in [
        (author, holder),
        (holder, author),
        (author, reader),
        (reader, author),
    ] {
        connect(from, to);
    }
    let first = call(
        author,
        json!({"op":"stage_network_publication","revision":revision,
            "topic":EVENT,"id":vec![1;16],"payload":[1]}),
    );
    let first = call(
        author,
        json!({"op":"adopt_publication","snapshot":first["snapshot"]}),
    );
    assert_eq!(first["sequence"], 1);
    let author_info: Value = serde_json::from_str(&describe(author).unwrap()).unwrap();
    call(
        reader,
        json!({"op":"fetch_recovery_range","peer":author_info["endpoint_key"],
            "revision":revision,"topics":[EVENT],"after":0,"through":1}),
    );
    assert_eq!(finish_range(&[author], reader)["packet_count"], 1);
    let recovered = call(reader, json!({"op":"stage_recovery_range"}));
    call(
        reader,
        json!({"op":"adopt_recovery","snapshot":recovered["snapshot"]}),
    );
    let pending = call(reader, json!({"op":"poll_pending_object"}));
    assert_eq!(pending["sequence"], 1);
    assert_eq!(pending["payload"], json!([1]));
    let acknowledged = call(
        reader,
        json!({"op":"stage_object_acknowledgement","member":pending["member"],
            "topic":pending["topic"],"counter":pending["counter"],"id":pending["id"]}),
    );
    call(
        reader,
        json!({"op":"adopt_reception","snapshot":acknowledged["snapshot"]}),
    );
    let saved_reader = call(reader, json!({"op":"seal_workspace"}));
    close(reader).unwrap();

    let tail = call(
        author,
        json!({"op":"stage_network_publication","revision":revision,
            "topic":EVENT,"id":vec![2;16],"payload":[2]}),
    );
    let tail = call(
        author,
        json!({"op":"adopt_publication","snapshot":tail["snapshot"]}),
    );
    assert_eq!(tail["sequence"], 2);
    call(
        holder,
        json!({"op":"fetch_recovery_range","peer":author_info["endpoint_key"],
            "revision":revision,"topics":[EVENT],"after":1,"through":2}),
    );
    assert_eq!(finish_range(&[author], holder)["packet_count"], 1);
    let retain_until = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let retained = call(
        holder,
        json!({"op":"stage_recovery_range","retain_until":retain_until}),
    );
    call(
        holder,
        json!({"op":"adopt_recovery","snapshot":retained["snapshot"]}),
    );

    let reader = create(Some(&[133; 32])).unwrap();
    call(
        reader,
        json!({"op":"restore_workspace","workspace":created["workspace"],
            "snapshot":saved_reader["snapshot"]}),
    );
    call(
        reader,
        json!({"op":"install_workspace_policy","revision":revision}),
    );
    let neighbors_before_holder =
        call(reader, json!({"op":"workspace_metrics"}))["gossip_neighbors"]
            .as_u64()
            .unwrap();
    connect(reader, holder);
    connect(holder, reader);
    let neighbor_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let neighbors = call(reader, json!({"op":"workspace_metrics"}))["gossip_neighbors"]
            .as_u64()
            .unwrap();
        if neighbors > neighbors_before_holder {
            break;
        }
        assert!(
            Instant::now() < neighbor_deadline,
            "retained holder did not join the reader's workspace overlay"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    close_for_impairment(author);

    let discovery_started = Instant::now();
    let presence_deadline = Instant::now() + Duration::from_secs(10);
    let gap = loop {
        let served = call(holder, json!({"op":"poll_admission"}));
        if !served.is_null() {
            assert!(matches!(
                served["state"].as_str(),
                Some("presence_replied" | "group_heads_replied")
            ));
        }
        call(reader, json!({"op":"poll_workspace_presence"}));
        let gap = call(
            reader,
            json!({"op":"next_group_gap", "author":
            created["member"]["id"], "topics":[EVENT]}),
        );
        if !gap.is_null() {
            break gap;
        }
        assert!(
            Instant::now() < presence_deadline,
            "retained group tail was not announced by the live holder"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let gap_detected = Instant::now();
    assert_eq!(gap["after"], 1);
    assert_eq!(gap["through"], 2);
    assert!(
        call(
            reader,
            json!({"op":"next_group_gap", "author":
        created["member"]["id"], "topics":[CURRENT]})
        )
        .is_null()
    );

    let request = json!({"op":"fetch_recovery_range","author":created["member"]["id"],
        "revision":revision,"topics":[EVENT]});
    let recovery_started = Instant::now();
    let recovery_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let started = call(reader, request.clone());
        if started["state"] == "recovery_range_pending" {
            break;
        }
        assert_eq!(started["state"], "recovery_source_waiting");
        assert!(
            Instant::now() < recovery_deadline,
            "holder did not become reachable"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let ready = finish_range(&[holder], reader);
    let ready_at = Instant::now();
    eprintln!(
        "group_tail_discovery_ms={} group_tail_range_ms={} group_tail_offline_to_ready_ms={}",
        gap_detected
            .saturating_duration_since(discovery_started)
            .as_millis(),
        ready_at
            .saturating_duration_since(recovery_started)
            .as_millis(),
        ready_at
            .saturating_duration_since(discovery_started)
            .as_millis(),
    );
    assert_eq!(ready["state"], "recovery_range_ready", "{ready}");
    let holder_info: Value = serde_json::from_str(&describe(holder).unwrap()).unwrap();
    assert_eq!(ready["peer"], holder_info["endpoint_key"]);
    assert_eq!(ready["after"], 1);
    assert_eq!(ready["through"], gap["through"]);
    assert_eq!(
        ready["packet_count"], 1,
        "replayed an already received prefix"
    );
    let recovered = call(reader, json!({"op":"stage_recovery_range"}));
    assert_eq!(recovered["publication_count"], 1);
    call(
        reader,
        json!({"op":"adopt_recovery","snapshot":recovered["snapshot"]}),
    );
    let pending = call(reader, json!({"op":"poll_pending_object"}));
    assert_eq!(pending["sequence"], 2);
    assert_eq!(pending["payload"], json!([2]));
    close_for_impairment(holder);
    close_for_impairment(reader);
}
