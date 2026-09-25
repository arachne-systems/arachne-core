//! ADR step 4: `next_event` end to end for the workspace events. A member
//! waits only on `next_event` while its peer serves requests; each event
//! kind must arrive for the work that makes it.
use arachne_runtime::{close, create, describe, execute, next_event};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const EVENT: &str = "atak/native/v1/chat";
const CURRENT: &str = "atak/native/v1/pli";

fn call(handle: i64, request: Value) -> Value {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap())
        .unwrap()
}

fn connect(from: i64, to: i64) {
    let info: Value = serde_json::from_str(&describe(to).unwrap()).unwrap();
    call(
        from,
        json!({"op":"add_address_hint","peer":info["endpoint_key"],
            "address":info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
    );
}

fn admit(author: i64, joiner: i64, invite: &Value, name: &str) -> Value {
    let begin = call(
        joiner,
        json!({"op":"begin_join","invitation":invite["invitation"],
            "checkpoint":invite["checkpoint"],"display_name":name}),
    );
    let staged = call(
        author,
        json!({"op":"stage_admission","authenticated_endpoint":begin["endpoint"],
            "request":begin["admission_request"]}),
    );
    call(author, json!({"op":"adopt_admission","snapshot":staged["snapshot"]}));
    call(
        author,
        json!({"op":"retained_admission","authenticated_endpoint":begin["endpoint"],
            "request":begin["admission_request"]}),
    )
}

/// Take one protected delivery out of the queue.
fn drain_protected(handle: i64) {
    let staged = call(handle, json!({"op":"poll_protected"}));
    if !staged.is_null() {
        call(handle, json!({"op":"adopt_reception","snapshot":staged["snapshot"]}));
    }
}

/// Wait on `next_event` alone until `wanted` comes. Deliveries that come
/// first are drained, as a host would.
fn wait_for(handle: i64, wanted: &str, seen: &mut Vec<String>) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "no {wanted} event; saw {seen:?}");
        let Some(event) = next_event(handle, left.as_millis() as u64).unwrap() else {
            continue;
        };
        let kind = serde_json::from_str::<Value>(&event).unwrap()["kind"]
            .as_str()
            .unwrap()
            .to_owned();
        seen.push(kind.clone());
        if kind == wanted {
            return;
        }
        match kind.as_str() {
            "protected_received" => drain_protected(handle),
            "control" => {
                call(handle, json!({"op":"poll_admission"}));
            }
            _ => {}
        }
    }
}

#[test]
fn next_event_reports_every_workspace_event_kind() {
    let author = create(Some(&[141; 32])).unwrap();
    let holder = create(Some(&[142; 32])).unwrap();
    let late = create(Some(&[143; 32])).unwrap();
    let created = call(author, json!({"op":"create_workspace","display_name":"Author"}));
    let staged = call(author, json!({"op":"stage_invitation","personal":false,"expires_at":0}));
    let invite = call(author, json!({"op":"adopt_admission","snapshot":staged["snapshot"]}))
        ["issued_invitation"]
        .clone();
    let reply = admit(author, holder, &invite, "Holder");
    let staged = call(
        holder,
        json!({"op":"stage_join","welcome":reply["welcome"],
            "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}),
    );
    call(holder, json!({"op":"adopt_join","snapshot":staged["snapshot"]}));
    connect(author, holder);
    connect(holder, author);
    let epoch = call(author, json!({"op":"member_roster"}))["epoch"].as_u64().unwrap();
    let revision = epoch + 1;
    for handle in [author, holder] {
        call(handle, json!({"op":"install_workspace_policy","revision":revision}));
    }
    // Let the two gossip overlays find each other.
    std::thread::sleep(Duration::from_millis(1500));
    // The author's host serves its peers' requests in the background.
    let stop = Arc::new(AtomicBool::new(false));
    let serving = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                if call(author, json!({"op":"poll_admission"})).is_null() {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        })
    };
    let author_info: Value = serde_json::from_str(&describe(author).unwrap()).unwrap();
    let workspace = created["workspace"].clone();
    for topic in [EVENT, CURRENT] {
        let subscribed = call(
            holder,
            json!({"op":"subscribe","workspace":workspace,"revision":revision,"topic":topic}),
        );
        assert_eq!(subscribed["failed"], json!([]), "{subscribed}");
    }
    let mut seen = Vec::new();

    // A protected publication arrives.
    let event = call(
        author,
        json!({"op":"stage_network_publication","revision":revision,
            "topic":EVENT,"id":vec![1;16],"payload":[42]}),
    );
    call(author, json!({"op":"adopt_publication","snapshot":event["snapshot"]}));
    wait_for(holder, "protected_received", &mut seen);
    drain_protected(holder);

    // A recovery range ends.
    call(
        holder,
        json!({"op":"fetch_recovery_range","peer":author_info["endpoint_key"],
            "revision":revision,"topics":[EVENT],"after":0,"through":1}),
    );
    wait_for(holder, "recovery_ready", &mut seen);
    assert!(!call(holder, json!({"op":"poll_recovery_range"})).is_null());
    let expires_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600;
    let retained = call(holder, json!({"op":"stage_recovery_range","retain_until":expires_at}));
    if !retained["snapshot"].is_null() {
        call(holder, json!({"op":"adopt_recovery","snapshot":retained["snapshot"]}));
    }

    // A current-view repair ends.
    let selector = vec![8; 32];
    let current = call(
        author,
        json!({"op":"stage_network_publication","revision":revision,
            "topic":CURRENT,"id":vec![2;16],"payload":[1],
            "current":{"selector":selector.clone(),"replacement_key":vec![9; 32],
                "expires_at":expires_at}}),
    );
    call(author, json!({"op":"adopt_publication","snapshot":current["snapshot"]}));
    call(
        holder,
        json!({"op":"fetch_current_view","peer":author_info["endpoint_key"],
            "authority":created["member"]["id"],"revision":revision,
            "topic":CURRENT,"selector":selector}),
    );
    wait_for(holder, "current_view_ready", &mut seen);
    assert!(!call(holder, json!({"op":"poll_current_view"})).is_null());
    call(holder, json!({"op":"cancel_current_view"}));

    // A presence answer comes back.
    call(holder, json!({"op":"poll_workspace_presence","announce":true}));
    wait_for(holder, "presence", &mut seen);
    call(holder, json!({"op":"poll_workspace_presence","announce":false}));

    // A membership step arrives by gossip when the author admits another.
    admit(author, late, &invite, "Late");
    wait_for(holder, "membership_changed", &mut seen);

    eprintln!("events seen: {seen:?}");
    stop.store(true, Ordering::Release);
    serving.join().unwrap();
    for handle in [late, holder, author] {
        close(handle).unwrap();
    }
}
