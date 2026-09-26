//! A3f: the runtime recovery ops recover an author's objects from an earlier
//! epoch that is still in the receive window, not only from the current one.
use arachne_runtime::{ErrorCode, MemoryProvider, close, describe, execute, execute_with_code};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

mod common;

const EVENT: &str = "atak/native/v1/chat";

fn call(handle: i64, request: Value) -> Value {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap())
        .unwrap()
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

#[test]
fn recovery_reaches_an_earlier_epoch_in_the_receive_window() {
    let author = common::stored(&[161; 32], &MemoryProvider::default());
    let reader = common::stored(&[162; 32], &MemoryProvider::default());
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
    // The reader is not subscribed: this object is missed live at epoch 2.
    let staged = call(
        author,
        json!({"op":"stage_network_publication","revision":3,"topic":EVENT,
            "id":(vec![7u8; 16]),"payload":[42]}),
    );
    let sent = adopt(author, "adopt_publication", &staged);
    let missed_epoch = sent["epoch"].as_u64().unwrap();
    assert_eq!(missed_epoch, 2);
    // One membership step moves both members to epoch 3.
    let staged = call(
        author,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    );
    let step = call(
        author,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )["step"]
        .clone();
    let staged = call(reader, json!({"op":"stage_admission_update","step":step}));
    let adopted = call(
        reader,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    );
    assert_eq!(adopted["epoch"], 3);
    for handle in [author, reader] {
        call(
            handle,
            json!({"op":"install_workspace_policy","revision":4}),
        );
    }
    connect(reader, author);
    let member = created["member"]["id"].clone();

    // An epoch outside the receive window is refused with its code.
    let error = execute_with_code(
        reader,
        &serde_json::to_vec(&json!({"op":"fetch_recovery_range","author":member,
            "revision":4,"topics":[EVENT],"epoch":99}))
        .unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::EpochMismatch, "{error}");

    // The missed epoch-2 object comes by automatic recovery at epoch 3.
    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = loop {
        let started = call(
            reader,
            json!({"op":"fetch_recovery_range","author":member,
                "revision":4,"topics":[EVENT],"epoch":missed_epoch}),
        );
        if started["state"] == "recovery_range_pending" {
            break finish_range(author, reader);
        }
        assert_eq!(started["state"], "recovery_source_waiting");
        assert!(Instant::now() < deadline, "author never became a source");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(ready["state"], "recovery_range_ready", "{ready}");
    assert_eq!(ready["epoch"], missed_epoch);
    let staged = call(reader, json!({"op":"stage_recovery_range"}));
    assert_eq!(staged["state"], "awaiting_recovery_save", "{staged}");
    assert_eq!(staged["publication_count"], 1);
    adopt(reader, "adopt_recovery", &staged);
    let pending = call(reader, json!({"op":"poll_pending_object"}));
    assert_eq!(pending["payload"], json!([42]));
    close(reader).unwrap();
    close(author).unwrap();
}
