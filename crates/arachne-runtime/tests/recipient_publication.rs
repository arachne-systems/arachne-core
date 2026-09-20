use arachne_runtime::{close, create, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

fn call(handle: i64, request: Value) -> Value {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap())
        .unwrap()
}

#[test]
fn recipient_publication_survives_receiver_restart_with_object_delivery_enabled() {
    let sender = create(Some(&[81; 32])).unwrap();
    let receiver = create(Some(&[82; 32])).unwrap();
    assert!(execute(sender, br#"{"op":"workspace_metrics"}"#).is_err());
    let workspace = call(
        sender,
        json!({"op":"create_workspace","display_name":"Publisher"}),
    );
    let invite = call(sender, json!({"op":"issue_invitation"}));
    let pending = call(
        receiver,
        json!({"op":"begin_join","invitation":invite["invitation"],
        "checkpoint":invite["checkpoint"],"display_name":"Subscriber"}),
    );
    let staged = call(
        sender,
        json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],
        "request":pending["admission_request"]}),
    );
    call(
        sender,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    );
    let reply = call(
        sender,
        json!({"op":"retained_admission","authenticated_endpoint":pending["endpoint"],
        "request":pending["admission_request"]}),
    );
    let staged = call(
        receiver,
        json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}),
    );
    call(
        receiver,
        json!({"op":"adopt_join","snapshot":staged["snapshot"]}),
    );
    for handle in [sender, receiver] {
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
    let info: Value = serde_json::from_str(&describe(receiver).unwrap()).unwrap();
    call(
        sender,
        json!({"op":"add_address_hint","peer":info["endpoint_key"],
        "address":info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    );
    let recipients = json!([pending["member"]["id"]]);
    let initial_metrics = call(receiver, json!({"op":"workspace_metrics"}));
    assert_eq!(initial_metrics["workspace"], workspace["workspace"]);
    assert_eq!(initial_metrics["pending_objects"], 0);
    let refused = call(
        sender,
        json!({"op":"stage_network_publication","revision":2,
        "topic":"streams/opaque","id":vec![0;16],"payload":[9],"recipients":recipients}),
    );
    let refused = call(
        sender,
        json!({"op":"adopt_publication","snapshot":refused["snapshot"]}),
    );
    assert_eq!(
        refused["admission"]["admitted"],
        json!([]),
        "unsubscribed recipient admitted"
    );
    assert_eq!(
        refused["admission"]["failed"][0]["peer"],
        info["endpoint_key"]
    );
    assert!(call(receiver, json!({"op":"poll_protected"})).is_null());
    let sender_info: Value = serde_json::from_str(&describe(sender).unwrap()).unwrap();
    call(
        receiver,
        json!({"op":"add_address_hint","peer":sender_info["endpoint_key"],
        "address":sender_info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    );
    let subscribed = call(
        receiver,
        json!({"op":"subscribe","workspace":workspace["workspace"],
        "revision":2,"topic":"streams/opaque"}),
    );
    assert_eq!(subscribed["failed"], json!([]));
    let staged = call(
        sender,
        json!({"op":"stage_network_publication","revision":2,
        "topic":"streams/opaque","id":vec![1;16],"payload":[0,255,42],"recipients":recipients}),
    );
    let sent = call(
        sender,
        json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
    );
    assert_eq!(sent["admission"]["admitted"], json!([info["endpoint_key"]]));
    let deadline = Instant::now() + Duration::from_secs(5);
    let staged = loop {
        let value = call(receiver, json!({"op":"poll_protected"}));
        if !value.is_null() {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "recipient received no publication"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    call(
        receiver,
        json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
    );
    let saved = call(receiver, json!({"op":"seal_workspace"}));
    let metrics = call(receiver, json!({"op":"workspace_metrics"}));
    assert!(
        metrics["received_bytes"].as_u64().unwrap()
            > initial_metrics["received_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        metrics["pending_objects"], 1,
        "Ordered-gap work is still pending"
    );
    assert!(
        metrics["paths"]
            .as_array()
            .unwrap()
            .iter()
            .all(|path| path["member"] == workspace["member"]["id"])
    );
    close(receiver).unwrap();
    let receiver = create(Some(&[82; 32])).unwrap();
    call(
        receiver,
        json!({"op":"restore_workspace","workspace":workspace["workspace"],"snapshot":saved["snapshot"]}),
    );
    let reopened = call(receiver, json!({"op":"workspace_metrics"}));
    assert_eq!(
        reopened["sent_bytes"], 0,
        "Transport totals reset on reopen"
    );
    assert_eq!(
        reopened["pending_objects"], 1,
        "Pending application work survives reopen"
    );
    call(
        receiver,
        json!({"op":"add_address_hint","peer":sender_info["endpoint_key"],
        "address":sender_info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    );
    call(
        receiver,
        json!({"op":"install_workspace_policy","revision":2}),
    );
    assert!(call(receiver, json!({"op":"poll_pending_object"})).is_null());
    let gap = call(receiver, json!({"op":"next_direct_gap"}));
    call(
        receiver,
        json!({"op":"fetch_direct_recovery","author":gap["author"],
            "revision":gap["revision"],"topic":gap["topic"],
            "recipients":gap["recipients"],"after":gap["after"],"through":gap["through"]}),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        call(sender, json!({"op":"poll_admission"}));
        let ready = call(receiver, json!({"op":"poll_direct_recovery"}));
        if !ready.is_null() {
            assert_eq!(ready["state"], "direct_recovery_ready");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "direct recovery did not complete"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let staged = call(receiver, json!({"op":"stage_direct_recovery"}));
    call(
        receiver,
        json!({"op":"adopt_recovery","snapshot":staged["snapshot"]}),
    );
    let missed = call(receiver, json!({"op":"poll_pending_object"}));
    assert_eq!(
        call(receiver, json!({"op":"workspace_metrics"}))["pending_objects"],
        2
    );
    assert_eq!(missed["payload"], json!([9]));
    let staged = call(
        receiver,
        json!({"op":"stage_object_acknowledgement","member":missed["member"],
            "topic":missed["topic"],"counter":missed["counter"],"id":missed["id"]}),
    );
    call(
        receiver,
        json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
    );
    let item = call(receiver, json!({"op":"poll_pending_object"}));
    assert_eq!(
        call(receiver, json!({"op":"workspace_metrics"}))["pending_objects"],
        1
    );
    assert_eq!(item["payload"], json!([0, 255, 42]));
    assert_eq!(item["recipients"], recipients);
    assert_eq!(item["sequence"], 2);
    // Recipient publications must not enter or advance group recovery history.
    let staged = call(
        sender,
        json!({"op":"stage_network_publication","revision":2,
        "topic":"streams/opaque","id":vec![2;16],"payload":[7]}),
    );
    let published = call(
        sender,
        json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
    );
    assert_eq!(published["sequence"], 1);
    close(sender).unwrap();
    close(receiver).unwrap();
}
