use arachne_node::Node;
use arachne_runtime::{
    close, create, describe, enable_record_storage, execute, execute_stored, save_candidate,
};
use arachne_security::{Invitation, PendingJoin};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

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

fn endpoint(value: &Value) -> [u8; 32] {
    bytes(value).try_into().unwrap()
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

#[test]
#[ignore = "explicit 500-client public runtime capacity run"]
fn public_runtime_admission_path_handles_500_authenticated_joiners() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    const MEMBERS: usize = 500;
    const RETRIES: usize = 16;
    let started = Instant::now();
    let owner = create(Some(&[17; 32])).unwrap();
    call(
        owner,
        json!({"op":"create_workspace","display_name":"Burst owner","workspace_name":"Capacity test"}),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    enable_record_storage(owner, &dir.path().join("owner.db"), &[17; 32]).unwrap();
    let invitation = call(owner, json!({"op":"issue_invitation"})).unwrap();
    let invitation_bytes = bytes(&invitation["invitation"]);
    let checkpoint = bytes(&invitation["checkpoint"]);
    let owner_info: Value = serde_json::from_str(&describe(owner).unwrap()).unwrap();
    let owner_peer = endpoint(&owner_info["endpoint_key"]);
    let owner_port = owner_info["bound_address"]
        .as_str()
        .unwrap()
        .rsplit_once(':')
        .unwrap()
        .1
        .parse::<u16>()
        .unwrap();
    let owner_address = SocketAddr::from(([127, 0, 0, 1], owner_port));

    let (initial_done_tx, initial_done_rx) = mpsc::channel();
    let (retry_tx, retry_rx) = mpsc::channel();
    let client_thread = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let mut binds = JoinSet::new();
            for index in 0..MEMBERS {
                binds.spawn(async move {
                    let mut seed = [0; 32];
                    seed[..8].copy_from_slice(&(index as u64 + 1000).to_be_bytes());
                    Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &seed)
                        .await
                        .map(|(node, _)| Arc::new(node))
                });
            }
            let mut nodes = Vec::with_capacity(MEMBERS);
            while let Some(result) = binds.join_next().await {
                nodes.push(result.unwrap().unwrap());
            }
            let invitation = Invitation::from_bytes(&invitation_bytes).unwrap();
            let packets: Vec<_> = nodes
                .iter()
                .map(|node| {
                    let peer = node.id();
                    let pending = PendingJoin::from_invitation(
                        &invitation,
                        &checkpoint,
                        peer,
                        "Burst member",
                    )
                    .unwrap();
                    admission_packet(
                        pending.admission_request().unwrap(),
                        "Burst member",
                        &checkpoint,
                    )
                })
                .collect();

            let mut first = JoinSet::new();
            let probe_node = Arc::clone(&nodes[0]);
            let probe = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                probe_node
                    .add_address_hint(owner_peer, owner_address)
                    .await?;
                probe_node.request_control(owner_peer, b"DFND\x01").await
            });
            for (node, packet) in nodes.iter().zip(&packets) {
                let node = Arc::clone(node);
                let packet = packet.clone();
                first.spawn(async move {
                    node.add_address_hint(owner_peer, owner_address).await?;
                    node.request_control(owner_peer, &packet).await
                });
            }
            let mut initial_queued = 0;
            while let Some(result) = first.join_next().await {
                let reply = result.unwrap().unwrap();
                let value: Value = serde_json::from_slice(&reply).unwrap();
                assert_eq!(
                    value["state"], "admission_queued",
                    "unexpected admission reply: {value}"
                );
                initial_queued += 1;
            }
            initial_done_tx.send(initial_queued).unwrap();
            assert_eq!(probe.await.unwrap().unwrap(), b"Unnamed Arachne device");
            retry_rx.recv().unwrap();

            let mut retry: JoinSet<Result<Vec<u8>, arachne_node::Error>> = JoinSet::new();
            for (node, packet) in nodes.iter().zip(&packets).take(RETRIES) {
                let node = Arc::clone(node);
                let packet = packet.clone();
                retry.spawn(async move {
                    for _ in 0..200 {
                        let reply = node.request_control(owner_peer, &packet).await?;
                        let state: Value = serde_json::from_slice(&reply).unwrap();
                        if state["state"] != "admission_queued" {
                            return Ok(reply);
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    panic!("retained admission did not become available");
                });
            }
            let mut retained = 0;
            while let Some(result) = retry.join_next().await {
                let reply = result.unwrap().unwrap();
                let value: Value = serde_json::from_slice(&reply).unwrap();
                assert!(
                    value["commit"].is_array(),
                    "unexpected retained reply: {value}"
                );
                retained += 1;
            }
            for node in nodes {
                Arc::try_unwrap(node).ok().unwrap().close().await;
            }
            retained
        })
    });

    let deadline = Instant::now() + Duration::from_secs(180);
    let mut batches = 0;
    let mut committed = 0;
    let mut initial_queued = None;
    while committed < MEMBERS {
        assert!(
            Instant::now() < deadline,
            "public runtime admission burst timed out"
        );
        if initial_queued.is_none() {
            initial_queued = initial_done_rx.try_recv().ok();
        }
        let value = call(owner, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "awaiting_save" {
            let count = value["admissions"].as_u64().unwrap() as usize;
            let snapshot = bytes(&value["snapshot"]);
            save_candidate(owner, &snapshot).unwrap();
            let adopted = execute_stored(owner, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&adopted[0]).unwrap()["members"],
                committed + count + 1
            );
            committed += count;
            batches += 1;
        } else if value["state"] == "approval_requested" {
            panic!("open invitation unexpectedly requested approval: {value}");
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(initial_queued, Some(MEMBERS));
    retry_tx.send(()).unwrap();
    while !client_thread.is_finished() {
        let value = call(owner, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "awaiting_save" {
            let snapshot = bytes(&value["snapshot"]);
            save_candidate(owner, &snapshot).unwrap();
            execute_stored(owner, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap();
            batches += 1;
        } else {
            assert!(
                value.is_null()
                    || value["state"] == "admission_replied"
                    || value["state"] == "nearby_identity_replied"
                    || value["state"] == "admission_queued",
                "unexpected retained retry state: {value}"
            );
        }
        thread::sleep(Duration::from_millis(2));
    }
    let retained = client_thread.join().unwrap();
    assert_eq!(retained, RETRIES);
    let roster = call(owner, json!({"op":"member_roster"})).unwrap();
    assert_eq!(roster["members"].as_array().unwrap().len(), MEMBERS + 1);
    close(owner).unwrap();
    println!(
        "public_runtime_admission_capacity members={MEMBERS} batches={batches} retained={retained} elapsed_ms={}",
        started.elapsed().as_millis()
    );
}
