//! A publication sent one policy revision behind the receiver's still
//! decrypts and lands. Routing accepts it only where both revisions grant,
//! so this never widens what the sender may publish.
use arachne_runtime::{close, create, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

fn call(handle: i64, request: Value) -> Value {
    let reply = execute(handle, &serde_json::to_vec(&request).unwrap())
        .unwrap_or_else(|error| panic!("{request}: {error}"));
    serde_json::from_slice(&reply).unwrap()
}

fn hint(from: i64, to: i64) {
    let info: Value = serde_json::from_str(&describe(to).unwrap()).unwrap();
    call(
        from,
        json!({"op":"add_address_hint","peer":info["endpoint_key"],
        "address":info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    );
}

#[test]
fn publication_one_revision_behind_is_received() {
    let sender = create(Some(&[91; 32])).unwrap();
    let receiver = create(Some(&[92; 32])).unwrap();
    let workspace = call(
        sender,
        json!({"op":"create_workspace","display_name":"Publisher"}),
    );
    let staged = call(
        sender,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    );
    let invite = call(
        sender,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )["issued_invitation"]
        .clone();
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
    let topics = json!(["streams/opaque"]);
    for handle in [sender, receiver] {
        // Object delivery is always on (A3); only the policy is installed.
        call(
            handle,
            json!({"op":"install_member_policy","revision":2,"topics":topics}),
        );
    }
    hint(sender, receiver);
    hint(receiver, sender);
    let subscribed = call(
        receiver,
        json!({"op":"subscribe","workspace":workspace["workspace"],
        "revision":2,"topic":"streams/opaque"}),
    );
    assert_eq!(subscribed["failed"], json!([]));
    // The receiver moves on; the sender has not installed revision 3 yet.
    call(
        receiver,
        json!({"op":"install_member_policy","revision":3,"topics":topics}),
    );
    let staged = call(
        sender,
        json!({"op":"stage_network_publication","revision":2,
        "topic":"streams/opaque","id":vec![1;16],"payload":[4,5,6]}),
    );
    let sent = call(
        sender,
        json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
    );
    let receiver_key =
        serde_json::from_str::<Value>(&describe(receiver).unwrap()).unwrap()["endpoint_key"]
            .clone();
    assert_eq!(sent["admission"]["queued"], json!(true), "{sent}");
    let deadline = Instant::now() + Duration::from_secs(5);
    let staged = loop {
        let value = call(receiver, json!({"op":"poll_protected"}));
        if !value.is_null() {
            break value;
        }
        assert!(Instant::now() < deadline, "receiver got no publication");
        std::thread::sleep(Duration::from_millis(5));
    };
    call(
        receiver,
        json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
    );
    let item = call(receiver, json!({"op":"poll_pending_object"}));
    assert_eq!(item["payload"], json!([4, 5, 6]));
    assert_eq!(item["revision"], 2, "{item}");

    // A direct publication one revision behind lands the same way.
    let recipients = json!([pending["member"]["id"]]);
    let staged = call(
        sender,
        json!({"op":"stage_network_publication","revision":2,"topic":"streams/opaque",
        "id":vec![2;16],"payload":[7],"recipients":recipients}),
    );
    let sent = call(
        sender,
        json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
    );
    assert_eq!(
        sent["admission"]["admitted"],
        json!([receiver_key]),
        "{sent}"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let staged = loop {
        let value = call(receiver, json!({"op":"poll_protected"}));
        if !value.is_null() {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "receiver got no direct publication"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    call(
        receiver,
        json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
    );

    // Two revisions behind is outside the window: nothing reaches the runtime.
    call(
        receiver,
        json!({"op":"install_member_policy","revision":4,"topics":topics}),
    );
    let staged = call(
        sender,
        json!({"op":"stage_network_publication","revision":2,
        "topic":"streams/opaque","id":vec![3;16],"payload":[8]}),
    );
    call(
        sender,
        json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        assert!(
            call(receiver, json!({"op":"poll_protected"})).is_null(),
            "a publication two revisions behind was received"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    close(sender).unwrap();
    close(receiver).unwrap();
}
