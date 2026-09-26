//! B7b: automatic recovery of large objects makes progress under the
//! per-author pending quota. The application acknowledges only after each
//! stage/adopt cycle, as a real host does.
use arachne_runtime::{MemoryProvider, close, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

mod common;

const EVENT: &str = "atak/native/v1/chat";
/// Full-size objects: 12 KiB payloads (zero-filled to keep the JSON request
/// under `MAX_REQUEST`). Two fit the 32 KiB author quota; one
/// 128 KiB reply carries many more.
const PAYLOAD: usize = 12 * 1024;
const OBJECTS: u64 = 12;

fn call(handle: i64, request: Value) -> Value {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap())
        .unwrap()
}

fn try_call(handle: i64, request: Value) -> Result<Value, String> {
    execute(handle, &serde_json::to_vec(&request).unwrap())
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

/// Adopt a staged candidate: save, read back and adopt in one step.
fn adopt(handle: i64, op: &str, staged: &Value) -> Value {
    call(handle, json!({"op":op,"candidate":staged["candidate"]}))
}

fn step(reply: &Value) -> Value {
    json!({"commit":reply["commit"],"authorization":reply["authorization"]})
}

fn issue_invitation(handle: i64) -> Value {
    let staged = call(
        handle,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    );
    call(
        handle,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )["issued_invitation"]
        .clone()
}

fn add(owner: i64, joiner: i64, invite: &Value, name: &str) {
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
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    );
    let reply = call(
        owner,
        json!({"op":"retained_admission","authenticated_endpoint":begin["endpoint"],
            "request":begin["admission_request"]}),
    );
    let staged = call(
        joiner,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":[step(&reply)]}),
    );
    call(
        joiner,
        json!({"op":"adopt_join","candidate":staged["candidate"]}),
    );
}

fn connect(from: i64, to: i64) {
    let info: Value = serde_json::from_str(&describe(to).unwrap()).unwrap();
    call(
        from,
        json!({"op":"add_address_hint","peer":info["endpoint_key"],
            "address":info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    );
}

fn finish_range(server: i64, client: i64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let served = call(server, json!({"op":"poll_admission"}));
        if !served.is_null() {
            assert_eq!(served["state"], "recovery_replied");
        }
        let result = call(client, json!({"op":"poll_recovery_range"}));
        if !result.is_null() {
            return result;
        }
        assert!(Instant::now() < deadline, "recovery did not complete");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Start one automatic request (no after/through) and wait for its result.
fn automatic_range(author: i64, reader: i64, member: &Value) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let started = call(
            reader,
            json!({"op":"fetch_recovery_range","author":member,
                "revision":3,"topics":[EVENT]}),
        );
        if started["state"] == "recovery_range_pending" {
            return finish_range(author, reader);
        }
        assert_eq!(started["state"], "recovery_source_waiting");
        assert!(Instant::now() < deadline, "author never became a source");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn number(pending: &Value) -> u64 {
    let payload: Vec<u8> = serde_json::from_value(pending["payload"].clone()).unwrap();
    assert_eq!(payload.len(), PAYLOAD);
    u64::from_be_bytes(payload[..8].try_into().unwrap())
}

fn acknowledge(handle: i64, pending: &Value) {
    let ack = call(
        handle,
        json!({"op":"stage_object_acknowledgement","member":pending["member"],
            "topic":pending["topic"],"counter":pending["counter"],"id":pending["id"]}),
    );
    adopt(handle, "adopt_reception", &ack);
}

#[test]
fn automatic_recovery_of_large_objects_progresses_under_author_quota() {
    let author = common::stored(&[131; 32], &MemoryProvider::default());
    let reader = common::stored(&[132; 32], &MemoryProvider::default());
    let created = call(
        author,
        json!({"op":"create_workspace","display_name":"Author"}),
    );
    let invite = issue_invitation(author);
    add(author, reader, &invite, "Reader");
    for handle in [author, reader] {
        call(
            handle,
            json!({"op":"install_workspace_policy","revision":3}),
        );
    }
    // The reader does not subscribe: every object is missed live and must
    // come by automatic recovery.
    for sequence in 1..=OBJECTS {
        let mut payload = vec![0u8; PAYLOAD];
        payload[..8].copy_from_slice(&sequence.to_be_bytes());
        let staged = call(
            author,
            json!({"op":"stage_network_publication","revision":3,"topic":EVENT,
                "id":u128::from(sequence).to_be_bytes(),"payload":payload}),
        );
        let sent = adopt(author, "adopt_publication", &staged);
        assert_eq!(sent["sequence"], sequence);
    }
    connect(reader, author);
    let member = created["member"]["id"].clone();

    let mut delivered = Vec::new();
    let mut accepted = 0u64;
    let mut cycles = 0;
    let mut first_range = None;
    while accepted < OBJECTS {
        cycles += 1;
        assert!(cycles <= OBJECTS, "recovery made no progress");
        let ready = automatic_range(author, reader, &member);
        assert_eq!(ready["state"], "recovery_range_ready");
        assert_eq!(ready["automatic_source"], true);
        assert_eq!(ready["after"], accepted);
        let through = ready["through"].as_u64().unwrap();
        first_range.get_or_insert(through);
        let staged = try_call(reader, json!({"op":"stage_recovery_range"}))
            .unwrap_or_else(|error| panic!("cycle {cycles}: stage failed: {error}"));
        assert_eq!(staged["state"], "awaiting_recovery_save");
        let count = staged["publication_count"].as_u64().unwrap();
        assert!(count >= 1, "cycle {cycles} admitted nothing");
        let progress = staged["accepted_through"].as_u64().unwrap();
        // Progress covers exactly what was admitted, never past the range.
        assert_eq!(progress, accepted + count);
        assert!(progress <= through);
        adopt(reader, "adopt_recovery", &staged);
        // The application drains and acknowledges only now.
        loop {
            let pending = call(reader, json!({"op":"poll_pending_object"}));
            if pending.is_null() {
                break;
            }
            delivered.push(number(&pending));
            acknowledge(reader, &pending);
        }
        assert_eq!(delivered.len() as u64, progress);
        accepted = progress;
    }
    // At least one served range was larger than what the quota admits.
    assert!(
        first_range.unwrap() > 2,
        "served range fit the quota anyway"
    );
    assert!(cycles > 1);
    assert_eq!(delivered, (1..=OBJECTS).collect::<Vec<_>>());
    // Nothing is left to recover, and nothing is delivered twice.
    let done = automatic_range(author, reader, &member);
    assert_eq!(done["state"], "recovery_source_unavailable");
    // An explicit replay of an early range stages every record again: all
    // are duplicates, so nothing is delivered twice.
    let info: Value = serde_json::from_str(&describe(author).unwrap()).unwrap();
    call(
        reader,
        json!({"op":"fetch_recovery_range","peer":info["endpoint_key"],"revision":3,
            "topics":[EVENT],"after":0,"through":2}),
    );
    assert_eq!(
        finish_range(author, reader)["state"],
        "recovery_range_ready"
    );
    assert_eq!(
        call(reader, json!({"op":"stage_recovery_range"}))["state"],
        "recovery_no_new_objects"
    );
    assert!(call(reader, json!({"op":"poll_pending_object"})).is_null());
    close(reader).unwrap();
    close(author).unwrap();
}

#[test]
fn automatic_recovery_waits_for_the_application_when_the_quota_is_full() {
    let author = common::stored(&[141; 32], &MemoryProvider::default());
    let reader = common::stored(&[142; 32], &MemoryProvider::default());
    let created = call(
        author,
        json!({"op":"create_workspace","display_name":"Author"}),
    );
    let invite = issue_invitation(author);
    add(author, reader, &invite, "Reader");
    for handle in [author, reader] {
        call(
            handle,
            json!({"op":"install_workspace_policy","revision":3}),
        );
    }
    for sequence in 1..=4u64 {
        let mut payload = vec![0u8; PAYLOAD];
        payload[..8].copy_from_slice(&sequence.to_be_bytes());
        let staged = call(
            author,
            json!({"op":"stage_network_publication","revision":3,"topic":EVENT,
                "id":u128::from(sequence).to_be_bytes(),"payload":payload}),
        );
        adopt(author, "adopt_publication", &staged);
    }
    connect(reader, author);
    let member = created["member"]["id"].clone();
    let ready = automatic_range(author, reader, &member);
    assert_eq!(ready["through"], 4);
    let staged = call(reader, json!({"op":"stage_recovery_range"}));
    assert_eq!(staged["accepted_through"], 2);
    adopt(reader, "adopt_recovery", &staged);
    // The application has not acknowledged: the author's quota is full, so
    // the next range admits nothing and claims no progress.
    let ready = automatic_range(author, reader, &member);
    assert_eq!(ready["after"], 2);
    let waiting = call(reader, json!({"op":"stage_recovery_range"}));
    assert_eq!(waiting["state"], "recovery_awaiting_application");
    assert_eq!(waiting["accepted_through"], 2);
    assert!(waiting.get("candidate").is_none());
    // After the application drains, recovery continues from the same point.
    for expected in 1..=2 {
        let pending = call(reader, json!({"op":"poll_pending_object"}));
        assert_eq!(number(&pending), expected);
        acknowledge(reader, &pending);
    }
    let ready = automatic_range(author, reader, &member);
    assert_eq!(ready["after"], 2);
    let staged = call(reader, json!({"op":"stage_recovery_range"}));
    assert_eq!(staged["accepted_through"], 4);
    assert_eq!(staged["publication_count"], 2);
    close(reader).unwrap();
    close(author).unwrap();
}
