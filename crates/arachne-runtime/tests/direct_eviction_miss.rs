//! B7e on the runtime path: when the receiver's direct record window
//! overflows past a gap, the skipped sequence is reported as missed
//! (`missing_count`), and the objects behind it are delivered in order.
use arachne_runtime::{MemoryProvider, close, describe, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

mod common;

const TOPIC: &str = "streams/opaque";
/// One more than the per-scope record window (32).
const LIVE_THROUGH: u64 = 34;

fn call(handle: i64, request: Value) -> Value {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap())
        .unwrap()
}

fn hint(from: i64, to: i64) {
    let info: Value = serde_json::from_str(&describe(to).unwrap()).unwrap();
    call(
        from,
        json!({"op":"add_address_hint","peer":info["endpoint_key"],
            "address":info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    );
}

fn publish(sender: i64, recipients: &Value, sequence: u64) -> Value {
    let staged = call(
        sender,
        json!({"op":"stage_network_publication","revision":3,"topic":TOPIC,
            "id":u128::from(sequence).to_be_bytes(),"payload":[sequence as u8],
            "recipients":recipients}),
    );
    call(
        sender,
        json!({"op":"adopt_publication","candidate":staged["candidate"]}),
    )
}

#[test]
fn evicting_past_a_direct_gap_reports_the_miss_and_keeps_order() {
    let sender = common::stored(&[151; 32], &MemoryProvider::default());
    let receiver = common::stored(&[152; 32], &MemoryProvider::default());
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
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
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
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
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
        json!({"op":"adopt_join","candidate":staged["candidate"]}),
    );
    for handle in [sender, receiver] {
        call(
            handle,
            json!({"op":"install_workspace_policy","revision":3}),
        );
    }
    hint(sender, receiver);
    let recipients = json!([pending["member"]["id"]]);
    // Sequence 1 goes out before the receiver subscribes: it is lost.
    let lost = publish(sender, &recipients, 1);
    assert_eq!(lost["admission"]["admitted"], json!([]));
    hint(receiver, sender);
    call(
        receiver,
        json!({"op":"subscribe","workspace":workspace["workspace"],
            "revision":3,"topic":TOPIC}),
    );
    let mut missing = 0;
    let mut adopted_missing = 0;
    for sequence in 2..=LIVE_THROUGH {
        let sent = publish(sender, &recipients, sequence);
        assert_eq!(sent["sequence"], sequence);
        let deadline = Instant::now() + Duration::from_secs(5);
        let staged = loop {
            let value = call(receiver, json!({"op":"poll_protected"}));
            if !value.is_null() {
                break value;
            }
            assert!(
                Instant::now() < deadline,
                "sequence {sequence} not received"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        let staged_missing = staged["missing_count"].as_u64().unwrap_or(0);
        missing += staged_missing;
        let adopted = call(
            receiver,
            json!({"op":"adopt_reception","candidate":staged["candidate"]}),
        );
        // B7f-1: the adoption reports the same miss as the staging reply.
        let adopted_here = adopted["missing_count"].as_u64().unwrap_or(0);
        assert_eq!(adopted_here, staged_missing, "sequence {sequence}");
        adopted_missing += adopted_here;
        if sequence < LIVE_THROUGH {
            assert!(
                call(receiver, json!({"op":"poll_pending_object"})).is_null(),
                "sequence {sequence} was delivered across the gap"
            );
        }
    }
    assert_eq!(
        missing, 1,
        "the skipped sequence was not reported as missed"
    );
    assert_eq!(adopted_missing, 1, "the adoption did not report the miss");
    assert!(call(receiver, json!({"op":"next_direct_gap"})).is_null());
    let mut delivered = Vec::new();
    loop {
        let pending = call(receiver, json!({"op":"poll_pending_object"}));
        if pending.is_null() {
            break;
        }
        delivered.push(pending["payload"][0].as_u64().unwrap());
        let ack = call(
            receiver,
            json!({"op":"stage_object_acknowledgement","member":pending["member"],
                "topic":pending["topic"],"counter":pending["counter"],"id":pending["id"]}),
        );
        call(
            receiver,
            json!({"op":"adopt_reception","candidate":ack["candidate"]}),
        );
    }
    assert_eq!(delivered, (2..=LIVE_THROUGH).collect::<Vec<_>>());
    close(receiver).unwrap();
    close(sender).unwrap();
}
