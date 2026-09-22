// Inquiries are answered from the committed view: no host poll, no session
// lock, no control queue. A request that asks for a membership change still
// goes to the host.
use arachne_node::Node;
use arachne_runtime::{
    close, create, describe, enable_record_storage, execute, execute_stored, save_candidate,
};
use arachne_security::{Invitation, PendingJoin};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|error| error.to_string())
}

fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect()
}

fn admission_packet(request: &[u8], name: &str, checkpoint: &[u8]) -> Vec<u8> {
    let mut packet = b"DFJA\x02".to_vec();
    packet.extend((request.len() as u32).to_be_bytes());
    packet.extend((name.len() as u16).to_be_bytes());
    packet.extend(request);
    packet.extend(name.as_bytes());
    packet.extend(checkpoint);
    packet
}

struct Owner {
    handle: i64,
    peer: [u8; 32],
    address: SocketAddr,
    invitation: Vec<u8>,
    checkpoint: Vec<u8>,
    _dir: tempfile::TempDir,
}

fn owner(seed: u8) -> Owner {
    let handle = create(Some(&[seed; 32])).unwrap();
    call(
        handle,
        json!({"op":"create_workspace","display_name":"Owner","workspace_name":"Committed view"}),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    enable_record_storage(handle, &dir.path().join("owner.db"), &[seed; 32]).unwrap();
    let staged = call(
        handle,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    )
    .unwrap();
    save_candidate(handle, &bytes(&staged["snapshot"])).unwrap();
    let invitation = call(
        handle,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap()["issued_invitation"]
        .clone();
    let info: Value = serde_json::from_str(&describe(handle).unwrap()).unwrap();
    let port: u16 = info["bound_address"]
        .as_str()
        .unwrap()
        .rsplit_once(':')
        .unwrap()
        .1
        .parse()
        .unwrap();
    Owner {
        handle,
        peer: bytes(&info["endpoint_key"]).try_into().unwrap(),
        address: SocketAddr::from(([127, 0, 0, 1], port)),
        invitation: bytes(&invitation["invitation"]),
        checkpoint: bytes(&invitation["checkpoint"]),
        _dir: dir,
    }
}

/// Drain, save, adopt, no pacing, until `done` or the deadline.
fn drive(owner: i64, deadline: Instant, mut done: impl FnMut(&Value) -> bool) -> bool {
    while Instant::now() < deadline {
        let value = call(owner, json!({"op":"poll_admission","profile":true})).unwrap();
        if value["state"] == "awaiting_save" {
            let snapshot = bytes(&value["snapshot"]);
            save_candidate(owner, &snapshot).unwrap();
            execute_stored(owner, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap();
        }
        if done(&value) {
            return true;
        }
        if value.is_null() {
            thread::sleep(Duration::from_millis(1));
        }
    }
    false
}

fn inquiries(owner: i64) -> u64 {
    call(owner, json!({"op":"workspace_metrics"})).unwrap()["control_timing"]["inquiry"]["count"]
        .as_u64()
        .unwrap()
}

/// One joiner that sends its exact join request each time `go` fires and
/// reports each reply. The request bytes never change, so every send is the
/// same admission attempt.
fn joiner(owner: &Owner, seed_index: u64) -> (mpsc::Sender<()>, mpsc::Receiver<Value>) {
    let (peer, address) = (owner.peer, owner.address);
    let (invitation, checkpoint) = (owner.invitation.clone(), owner.checkpoint.clone());
    let (go, asked) = mpsc::channel::<()>();
    let (replied, replies) = mpsc::channel();
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let mut seed = [0; 32];
            seed[..8].copy_from_slice(&seed_index.to_be_bytes());
            let (node, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &seed)
                .await
                .unwrap();
            let invitation = Invitation::from_bytes(&invitation).unwrap();
            let pending =
                PendingJoin::from_invitation(&invitation, &checkpoint, node.id(), "Joiner").unwrap();
            let packet = admission_packet(pending.admission_request().unwrap(), "Joiner", &checkpoint);
            node.add_address_hint(peer, address).await.unwrap();
            while asked.recv().is_ok() {
                let reply = node.request_control(peer, &packet).await.unwrap();
                replied.send(serde_json::from_slice(&reply).unwrap()).unwrap();
            }
        })
    });
    (go, replies)
}

#[test]
fn a_retained_result_is_answered_while_the_host_never_polls() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(61);
    let (go, replies) = joiner(&owner, 6100);

    // First ask: a membership change. The host drives it, as always.
    go.send(()).unwrap();
    let mut admitted = None;
    assert!(drive(owner.handle, Instant::now() + Duration::from_secs(20), |_| {
        admitted = replies.try_recv().ok();
        admitted.is_some()
    }));
    let admitted: Value = admitted.unwrap();
    assert!(admitted["commit"].is_array(), "{admitted}");
    let before = inquiries(owner.handle);

    // Second ask: the result is retained, so this is an inquiry. From here on
    // nobody polls the owner; only the committed view can answer.
    go.send(()).unwrap();
    let again = replies
        .recv_timeout(Duration::from_secs(5))
        .expect("no answer without a host poll");
    assert_eq!(again["commit"], admitted["commit"]);
    assert_eq!(again["welcome"], admitted["welcome"]);
    assert_eq!(inquiries(owner.handle), before + 1);
    close(owner.handle).unwrap();
}

#[test]
fn a_new_join_request_is_a_change_and_goes_to_the_host() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(62);
    let (go, replies) = joiner(&owner, 6200);
    go.send(()).unwrap();

    // Unanswered while the host does not poll: the view must not admit anyone.
    assert!(replies.recv_timeout(Duration::from_millis(500)).is_err());

    let mut intake = false;
    let mut reply = None;
    assert!(drive(owner.handle, Instant::now() + Duration::from_secs(20), |value| {
        intake |= value["intake"] == json!(true);
        reply = replies.try_recv().ok();
        reply.is_some()
    }));
    assert!(intake, "the host never saw the join request");
    assert!(reply.unwrap()["commit"].is_array());
    assert_eq!(inquiries(owner.handle), 0, "a membership change was answered as an inquiry");
    close(owner.handle).unwrap();
}

#[test]
fn an_invitation_checkpoint_is_answered_while_the_host_never_polls() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(63);
    let late = create(Some(&[64; 32])).unwrap();
    call(
        late,
        json!({"op":"add_address_hint","peer":owner.peer,"address":owner.address.to_string()}),
    )
    .unwrap();
    // Nobody polls the owner. Without the committed view this call runs into
    // the 30 s control deadline.
    let started = Instant::now();
    let fetched = call(
        late,
        json!({"op":"fetch_invitation_checkpoint","peer":owner.peer,"invitation":owner.invitation}),
    )
    .unwrap();
    assert_eq!(bytes(&fetched["checkpoint"]), owner.checkpoint);
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    assert_eq!(inquiries(owner.handle), 1);
    close(late).unwrap();
    close(owner.handle).unwrap();
}

/// A/B receipt, not a gate. N admitted joiners ask for their retained result
/// at the same moment while the host polls one request per 250 ms, the shape
/// of a busy tablet. With the committed view the host pace does not matter;
/// without it (comment out `set_inquiry_responder` in `create_endpoint`) every
/// answer waits its turn in the host queue.
/// Run: cargo test -p arachne-runtime --test committed_view bench -- --ignored --nocapture
#[test]
#[ignore]
fn bench_inquiries_under_a_paced_host() {
    const JOINERS: u64 = 32;
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(65);
    let joiners: Vec<_> = (0..JOINERS).map(|index| joiner(&owner, 6500 + index)).collect();
    for (go, _) in &joiners {
        go.send(()).unwrap();
    }
    let mut admitted = 0;
    assert!(drive(owner.handle, Instant::now() + Duration::from_secs(120), |_| {
        admitted += joiners.iter().filter(|(_, replies)| replies.try_recv().is_ok()).count() as u64;
        admitted == JOINERS
    }));

    let started = Instant::now();
    for (go, _) in &joiners {
        go.send(()).unwrap();
    }
    let mut latencies: Vec<u128> = Vec::new();
    let mut answered = vec![false; joiners.len()];
    while latencies.len() < joiners.len() {
        assert!(started.elapsed() < Duration::from_secs(120), "{} of {JOINERS} answered", latencies.len());
        // The paced host: one control request, then a 250 ms tick.
        let _ = call(owner.handle, json!({"op":"poll_admission"})).unwrap();
        let tick = Instant::now();
        while tick.elapsed() < Duration::from_millis(250) && latencies.len() < joiners.len() {
            for (index, (_, replies)) in joiners.iter().enumerate() {
                if !answered[index] && replies.try_recv().is_ok() {
                    answered[index] = true;
                    latencies.push(started.elapsed().as_millis());
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
    latencies.sort_unstable();
    let timing = call(owner.handle, json!({"op":"workspace_metrics"})).unwrap()["control_timing"].clone();
    println!(
        "BENCH {}",
        json!({"joiners":JOINERS, "p50_ms":latencies[latencies.len() / 2],
            "p95_ms":latencies[latencies.len() * 95 / 100], "max_ms":latencies[latencies.len() - 1],
            "control_timing":timing})
    );
    close(owner.handle).unwrap();
}

/// Admit `joiner` to `admin`'s workspace in-process (no network), as the
/// management tests do.
fn add_member(admin: i64, joiner: i64, name: &str) {
    let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
    let begin = call(
        joiner,
        json!({"op":"begin_join","invitation":invite["invitation"],"checkpoint":invite["checkpoint"],"display_name":name}),
    )
    .unwrap();
    let staged = call(
        admin,
        json!({"op":"stage_admission","authenticated_endpoint":begin["endpoint"],"request":begin["admission_request"]}),
    )
    .unwrap();
    call(admin, json!({"op":"adopt_admission","snapshot":staged["snapshot"]})).unwrap();
    let reply = call(
        admin,
        json!({"op":"retained_admission","authenticated_endpoint":begin["endpoint"],"request":begin["admission_request"]}),
    )
    .unwrap();
    let steps = json!([{"commit":reply["commit"],"authorization":reply["authorization"]}]);
    let staged = call(joiner, json!({"op":"stage_join","welcome":reply["welcome"],"commits":steps})).unwrap();
    call(joiner, json!({"op":"adopt_join","snapshot":staged["snapshot"]})).unwrap();
}

#[test]
fn a_membership_query_is_answered_while_the_host_never_polls() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[66; 32])).unwrap();
    call(admin, json!({"op":"create_workspace","display_name":"Owner"})).unwrap();
    let member = create(Some(&[67; 32])).unwrap();
    add_member(admin, member, "Field member");
    let info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
    let address = info["bound_address"].as_str().unwrap().replace("0.0.0.0:", "127.0.0.1:");
    call(member, json!({"op":"add_address_hint","peer":info["endpoint_key"],"address":address})).unwrap();
    let member_info: Value = serde_json::from_str(&describe(member).unwrap()).unwrap();

    // Nobody polls the owner. Before, this query waited in the host queue
    // until the 30 s control deadline (three tablets, 500 joiners).
    let started = Instant::now();
    call(member, json!({"op":"fetch_membership_update","peer":info["endpoint_key"]})).unwrap();
    let reply = loop {
        let value = call(member, json!({"op":"poll_membership_update"})).unwrap();
        if !value.is_null() {
            break value;
        }
        assert!(started.elapsed() < Duration::from_secs(5), "no answer without a host poll");
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(reply["state"], "membership_current", "{reply}");
    assert_eq!(inquiries(admin), 1);

    // The query carried the member's signed name. It is retained without
    // the host, so the owner's roster names the member at once.
    let roster = call(admin, json!({"op":"member_roster"})).unwrap();
    let named: Vec<_> = roster["members"].as_array().unwrap().iter()
        .filter(|entry| entry["display_name"] == "Field member").collect();
    assert_eq!(named.len(), 1, "{roster}");

    // The host still hears which current member asked (it picks a peer from it).
    let event = call(admin, json!({"op":"poll_admission"})).unwrap();
    assert_eq!(event["state"], "membership_replied", "{event}");
    assert_eq!(event["peer"], member_info["endpoint_key"]);
    assert!(call(admin, json!({"op":"poll_admission"})).unwrap().is_null());
    close(member).unwrap();
    close(admin).unwrap();
}
