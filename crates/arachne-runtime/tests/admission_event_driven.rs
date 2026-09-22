use arachne_node::Node;
use arachne_runtime::{
    close, create, describe, enable_record_storage, execute, execute_stored, restore_record_storage,
    save_candidate, wait_for_work,
};
use arachne_security::{Invitation, PendingJoin};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
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

fn admission_result_packet(reply: &Value) -> Vec<u8> {
    let reply = serde_json::to_vec(reply).unwrap();
    let mut packet = b"DFAR\x01".to_vec();
    packet.extend((reply.len() as u32).to_be_bytes());
    packet.extend(reply);
    packet
}

fn complete_join(handle: i64) -> Value {
    loop {
        let value = call(handle, json!({"op":"drive_join"})).unwrap();
        match value["state"].as_str() {
            Some("workspace_joined") => return value,
            Some("admission_pending") => assert!(wait_for_work(handle).unwrap()),
            Some("admission_waiting") => continue,
            state => panic!("unexpected join state: {state:?}"),
        }
    }
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
    let created = call(
        handle,
        json!({"op":"create_workspace","display_name":"Owner","workspace_name":"Event driven"}),
    )
    .unwrap();
    assert_eq!(created["activity"]["state"], "active");
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

async fn joiner(seed_index: u64, owner: &Owner) -> (Arc<Node>, Vec<u8>) {
    let mut seed = [0; 32];
    seed[..8].copy_from_slice(&seed_index.to_be_bytes());
    let (node, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &seed)
        .await
        .unwrap();
    let invitation = Invitation::from_bytes(&owner.invitation).unwrap();
    let pending =
        PendingJoin::from_invitation(&invitation, &owner.checkpoint, node.id(), "Joiner").unwrap();
    let packet = admission_packet(pending.admission_request().unwrap(), "Joiner", &owner.checkpoint);
    node.add_address_hint(owner.peer, owner.address).await.unwrap();
    (Arc::new(node), packet)
}

/// Drive the owner the way the Task 3 host does: drain, save, adopt, no pacing.
/// Returns when `done` reports true or the deadline passes.
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

#[test]
fn queued_admission_rearms_the_host_for_staging() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(83);
    let (reply_tx, reply_rx) = mpsc::channel();
    let peer = owner.peer;
    let address = owner.address;
    let invitation = owner.invitation.clone();
    let checkpoint = owner.checkpoint.clone();
    let requester = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (node, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[84; 32])
                .await
                .unwrap();
            let invitation = Invitation::from_bytes(&invitation).unwrap();
            let pending =
                PendingJoin::from_invitation(&invitation, &checkpoint, node.id(), "Joiner")
                    .unwrap();
            let packet = admission_packet(
                pending.admission_request().unwrap(),
                "Joiner",
                &checkpoint,
            );
            node.add_address_hint(peer, address).await.unwrap();
            reply_tx.send(node.request_control(peer, &packet).await).unwrap();
        });
    });

    assert!(wait_for_work(owner.handle).unwrap());
    assert_eq!(
        call(owner.handle, json!({"op":"drive_workspace"})).unwrap()["state"],
        "admission_queued"
    );
    let (wake_tx, wake_rx) = mpsc::channel();
    let owner_handle = owner.handle;
    let waiter = thread::spawn(move || wake_tx.send(wait_for_work(owner_handle)));
    match wake_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => assert!(result.unwrap()),
        Err(_) => {
            close(owner.handle).unwrap();
            waiter.join().unwrap().unwrap();
            requester.join().unwrap();
            panic!("queued admission did not rearm the host");
        }
    }
    let committed = call(owner.handle, json!({"op":"drive_workspace"})).unwrap();
    assert_eq!(committed["state"], "workspace_committed");
    assert_eq!(committed["results_delivered"], 1);
    assert_eq!(committed["results_pushed"], 0);
    assert!(reply_rx.recv_timeout(Duration::from_secs(2)).unwrap().is_ok());
    waiter.join().unwrap().unwrap();
    requester.join().unwrap();
    close(owner.handle).unwrap();
}

#[test]
fn rust_driver_commits_and_replies_without_host_candidate_steps() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(84);
    let path = owner._dir.path().join("owner.db");
    let (reply_tx, reply_rx) = mpsc::channel();
    let peer = owner.peer;
    let address = owner.address;
    let invitation = owner.invitation.clone();
    let checkpoint = owner.checkpoint.clone();
    let requester = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (node, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[85; 32])
                .await
                .unwrap();
            let invitation = Invitation::from_bytes(&invitation).unwrap();
            let pending = PendingJoin::from_invitation(&invitation, &checkpoint, node.id(), "Joiner").unwrap();
            let packet = admission_packet(pending.admission_request().unwrap(), "Joiner", &checkpoint);
            node.add_address_hint(peer, address).await.unwrap();
            reply_tx.send(node.request_control(peer, &packet).await).unwrap();
        });
    });

    assert!(wait_for_work(owner.handle).unwrap());
    let committed = loop {
        let value = call(owner.handle, json!({"op":"drive_workspace"})).unwrap();
        if value["state"] == "workspace_committed" {
            break value;
        }
        assert_eq!(value["state"], "admission_queued");
    };
    assert_eq!(committed["state"], "workspace_committed");
    assert_eq!(committed["members"], 2);
    let reply: Value = serde_json::from_slice(&reply_rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap()).unwrap();
    assert!(reply.get("welcome").is_some());
    requester.join().unwrap();

    close(owner.handle).unwrap();
    let reopened = create(Some(&[84; 32])).unwrap();
    assert_eq!(restore_record_storage(reopened, &path, &[84; 32], bytes(&committed["workspace"]).try_into().unwrap()).unwrap()["members"], 2);
    close(reopened).unwrap();
}

#[test]
fn rust_join_driver_persists_iroh_peer_and_adopts_the_welcome() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(86);
    let joiner_dir = tempfile::tempdir().unwrap();
    let joiner = create(Some(&[87; 32])).unwrap();
    let pending = call(
        joiner,
        json!({"op":"begin_join","invitation":owner.invitation,"checkpoint":owner.checkpoint,
            "display_name":"Joiner","peers":[owner.peer]}),
    )
    .unwrap();
    assert_eq!(pending["activity"]["state"], "joining");
    assert!(call(joiner, json!({"op":"create_workspace","display_name":"stale"})).is_err());
    assert_eq!(call(joiner, json!({"op":"workspace_state"})).unwrap()["activity"]["state"], "joining");
    let workspace: [u8; 32] = bytes(&pending["workspace"]).try_into().unwrap();
    let path = joiner_dir.path().join("joiner.db");
    enable_record_storage(joiner, &path, &[87; 32]).unwrap();
    assert_eq!(call(joiner, json!({"op":"workspace_state"})).unwrap()["activity"]["state"], "joining");
    call(joiner, json!({"op":"add_address_hint","peer":owner.peer,"address":owner.address.to_string()})).unwrap();

    let requester = thread::spawn(move || complete_join(joiner));
    assert!(wait_for_work(owner.handle).unwrap());
    loop {
        let value = call(owner.handle, json!({"op":"drive_workspace"})).unwrap();
        if value["state"] == "workspace_committed" {
            break;
        }
        assert_eq!(value["state"], "admission_queued");
    }
    let joined = requester.join().unwrap();
    assert_eq!(joined["state"], "workspace_joined");
    assert_eq!(joined["activity"]["state"], "active");
    assert_eq!(joined["members"], 2);
    assert!(call(joiner, json!({"op":"drive_join"})).is_err());
    assert_eq!(call(joiner, json!({"op":"workspace_state"})).unwrap()["activity"]["state"], "active");

    close(joiner).unwrap();
    let reopened = create(Some(&[87; 32])).unwrap();
    let restored = restore_record_storage(reopened, &path, &[87; 32], workspace).unwrap();
    assert_eq!(restored["members"], 2);
    assert_eq!(restored["activity"]["state"], "active");
    assert_eq!(call(reopened, json!({"op":"workspace_state"})).unwrap()["activity"]["state"], "active");
    close(reopened).unwrap();
    close(owner.handle).unwrap();
}

#[test]
fn rust_join_driver_resumes_the_persisted_iroh_peer_after_restart() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(88);
    let joiner_dir = tempfile::tempdir().unwrap();
    let path = joiner_dir.path().join("joiner.db");
    let joiner = create(Some(&[89; 32])).unwrap();
    let pending = call(
        joiner,
        json!({"op":"begin_join","invitation":owner.invitation,"checkpoint":owner.checkpoint,
            "display_name":"Joiner","peers":[owner.peer]}),
    )
    .unwrap();
    let workspace: [u8; 32] = bytes(&pending["workspace"]).try_into().unwrap();
    enable_record_storage(joiner, &path, &[89; 32]).unwrap();
    close(joiner).unwrap();

    let resumed = create(Some(&[89; 32])).unwrap();
    let restored = restore_record_storage(resumed, &path, &[89; 32], workspace).unwrap();
    assert_eq!(restored["state"], "pending");
    assert_eq!(restored["activity"]["state"], "joining");
    call(resumed, json!({"op":"add_address_hint","peer":owner.peer,"address":owner.address.to_string()})).unwrap();

    let requester = thread::spawn(move || complete_join(resumed));
    assert!(wait_for_work(owner.handle).unwrap());
    loop {
        let value = call(owner.handle, json!({"op":"drive_workspace"})).unwrap();
        if value["state"] == "workspace_committed" {
            break;
        }
        assert_eq!(value["state"], "admission_queued");
    }
    assert_eq!(requester.join().unwrap()["state"], "workspace_joined");
    close(owner.handle).unwrap();
}

#[test]
fn fresh_pending_join_reports_remove_and_reinvite_recovery() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(91);
    let first = create(Some(&[92; 32])).unwrap();
    let pending = call(
        first,
        json!({"op":"begin_join","invitation":owner.invitation,
            "checkpoint":owner.checkpoint,"display_name":"Recovered member","peers":[owner.peer]}),
    )
    .unwrap();
    let staged = call(
        owner.handle,
        json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],
            "request":pending["admission_request"]}),
    )
    .unwrap();
    save_candidate(owner.handle, &bytes(&staged["snapshot"])).unwrap();
    execute_stored(owner.handle, br#"{"op":"adopt_admission"}"#, &bytes(&staged["snapshot"]))
        .unwrap();
    close(first).unwrap();

    // Same endpoint, fresh pending credentials: the original local MLS state
    // is gone, so byte-exact retained-admission recovery is impossible.
    let fresh = create(Some(&[92; 32])).unwrap();
    let fresh_pending = call(
        fresh,
        json!({"op":"begin_join","invitation":owner.invitation,
            "checkpoint":owner.checkpoint,"display_name":"Recovered member","peers":[owner.peer]}),
    )
    .unwrap();
    assert_eq!(fresh_pending["endpoint"], pending["endpoint"]);
    call(
        fresh,
        json!({"op":"add_address_hint","peer":owner.peer,"address":owner.address.to_string()}),
    )
    .unwrap();

    let requester = thread::spawn(move || {
        call(fresh, json!({"op":"request_admission","peer":owner.peer}))
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let owner_event = loop {
        let value = call(owner.handle, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "admission_replied" {
            break value;
        }
        assert!(Instant::now() < deadline, "fresh admission was not rejected");
        thread::sleep(Duration::from_millis(5));
    };
    let joiner_reply = requester.join().unwrap().unwrap();
    assert_eq!(joiner_reply["state"], "admission_recovery_required");
    assert_eq!(joiner_reply["reason"], "member_already_admitted");
    assert_eq!(joiner_reply["recovery"], "remove_and_reinvite");
    assert_eq!(owner_event["reason"], "member_already_admitted");
    assert_eq!(owner_event["recovery"], "remove_and_reinvite");
    assert_eq!(owner_event["display_name"], "Recovered member");
    close(owner.handle).unwrap();
}

#[test]
fn rust_reset_invalidates_native_state_and_clears_the_projection() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let secret = [90; 32];
    let handle = create(Some(&secret)).unwrap();
    let created = call(
        handle,
        json!({"op":"create_workspace","display_name":"Owner","workspace_name":"Reset me"}),
    )
    .unwrap();
    let workspace: [u8; 32] = bytes(&created["workspace"]).try_into().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("workspace.db");
    enable_record_storage(handle, &path, &secret).unwrap();
    assert_eq!(
        call(handle, json!({"op":"workspace_state"})).unwrap()["activity"]["state"],
        "active"
    );

    let reset = call(handle, json!({"op":"reset_workspace"})).unwrap();
    assert_eq!(reset["state"], "reset");
    assert_eq!(reset["changed"], true);
    assert_eq!(reset["durable"], true);
    assert_eq!(reset["reset_activity"]["state"], "resetting");
    assert_eq!(reset["activity"]["state"], "empty");
    assert_eq!(
        call(handle, json!({"op":"workspace_state"})).unwrap()["workspace_ready"],
        false
    );

    let again = call(handle, json!({"op":"reset_workspace"})).unwrap();
    assert_eq!(again["state"], "reset");
    assert_eq!(again["changed"], false);
    assert_eq!(again["activity"]["state"], "empty");
    close(handle).unwrap();

    let reopened = create(Some(&secret)).unwrap();
    let error = restore_record_storage(reopened, &path, &secret, workspace).unwrap_err();
    assert_eq!(error, "native record store was reset");
    close(reopened).unwrap();
}

#[test]
fn a_busy_inbox_cannot_delay_a_small_batch_until_it_drains() {
    // Three distinct attempts, each resent 32 times, all waiting in the owner's
    // inbox before the owner reads anything. The queue never reaches the
    // 16-attempt cap and an admission packet is waiting on every read, so the
    // only thing that can release the batch early is a count of reads. The
    // old trigger (a 4 s clock, or an empty inbox) staged only after the owner
    // had read every duplicate. Counted in reads, not seconds, so the proof
    // does not depend on how fast this machine drains the inbox.
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(51);
    let (peer, address) = (owner.peer, owner.address);
    let (invitation, checkpoint) = (owner.invitation.clone(), owner.checkpoint.clone());
    let clients = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let shadow = Owner {
                handle: 0,
                peer,
                address,
                invitation,
                checkpoint,
                _dir: tempfile::tempdir().unwrap(),
            };
            let mut tasks = tokio::task::JoinSet::new();
            for index in 0..3u64 {
                let (node, packet) = joiner(5100 + index, &shadow).await;
                // 32 is the per-peer exchange budget (arachne-node budget.rs).
                for _ in 0..32 {
                    let (node, packet) = (Arc::clone(&node), packet.clone());
                    tasks.spawn(async move {
                        let _ = node.request_control(peer, &packet).await;
                    });
                }
            }
            while tasks.join_next().await.is_some() {}
        })
    });
    // Test code may sleep: let every request land before the owner reads.
    thread::sleep(Duration::from_secs(3));

    let mut admission_reads = 0usize;
    let mut reads_before_stage: Option<usize> = None;
    drive(owner.handle, Instant::now() + Duration::from_secs(30), |value| {
        if value["state"] == "admission_queued" {
            admission_reads += 1;
        }
        if value["state"] == "awaiting_save" && reads_before_stage.is_none() {
            reads_before_stage = Some(admission_reads);
        }
        reads_before_stage.is_some()
    });
    // Keep answering so every waiting request completes and the clients end.
    drive(owner.handle, Instant::now() + Duration::from_secs(30), |_| clients.is_finished());
    clients.join().unwrap();
    close(owner.handle).unwrap();

    let reads = reads_before_stage.expect("no batch was staged under a busy inbox");
    assert!(
        reads <= 16 + 3,
        "staged after {reads} admission reads: the batch waited for the inbox to drain, not for a count"
    );
}

#[test]
fn one_request_is_enough_the_result_arrives_on_the_same_exchange() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(52);
    let (peer, address) = (owner.peer, owner.address);
    let (invitation, checkpoint) = (owner.invitation.clone(), owner.checkpoint.clone());
    let client = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let shadow = Owner {
                handle: 0,
                peer,
                address,
                invitation,
                checkpoint,
                _dir: tempfile::tempdir().unwrap(),
            };
            let (node, packet) = joiner(5200, &shadow).await;
            // Exactly one request. No retry loop.
            let reply = node.request_control(peer, &packet).await.unwrap();
            serde_json::from_slice::<Value>(&reply).unwrap()
        })
    });

    let started = Instant::now();
    let mut delivered = 0;
    drive(owner.handle, Instant::now() + Duration::from_secs(20), |_| client.is_finished());
    let metrics = call(owner.handle, json!({"op":"workspace_metrics"})).unwrap();
    let reply = client.join().unwrap();
    delivered += usize::from(reply["commit"].is_array());
    close(owner.handle).unwrap();

    assert_eq!(delivered, 1, "the single request got {reply} instead of its result");
    assert!(reply["welcome"].is_array());
    assert_eq!(metrics["admission_waiters"], 0);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "one local join took {:?}",
        started.elapsed()
    );
}

#[test]
fn expired_admission_exchange_receives_a_pushed_result_without_retry() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(57);
    let (peer, address) = (owner.peer, owner.address);
    let (invitation, checkpoint) = (owner.invitation.clone(), owner.checkpoint.clone());
    let (expire_tx, expire_rx) = mpsc::channel();
    let (expired_tx, expired_rx) = mpsc::channel();
    let (commit_tx, commit_rx) = mpsc::channel();
    let client = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (mut node, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[58; 32])
                .await
                .unwrap();
            let invitation = Invitation::from_bytes(&invitation).unwrap();
            let pending = PendingJoin::from_invitation(&invitation, &checkpoint, node.id(), "Joiner").unwrap();
            let packet = admission_packet(pending.admission_request().unwrap(), "Joiner", &checkpoint);
            node.add_address_hint(peer, address).await.unwrap();
            let request = tokio::spawn(node.request_control(peer, &packet));
            tokio::task::spawn_blocking(move || expire_rx.recv().unwrap())
                .await
                .unwrap();
            request.abort();
            let _ = request.await;
            expired_tx.send(()).unwrap();
            tokio::task::spawn_blocking(move || commit_rx.recv().unwrap())
                .await
                .unwrap();

            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(incoming) = node.poll_control() {
                    let payload = incoming.payload().to_vec();
                    assert!(payload.starts_with(b"DFAR\x01"), "unexpected push: {payload:?}");
                    incoming.respond(vec![1]).unwrap();
                    return payload;
                }
                assert!(Instant::now() < deadline, "owner did not push the retained admission result");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    let queued = loop {
        let value = call(owner.handle, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "admission_queued" {
            break value;
        }
        assert!(Instant::now() < deadline, "admission request never reached the owner");
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(queued["state"], "admission_queued");
    expire_tx.send(()).unwrap();
    expired_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let staged = loop {
        let value = call(owner.handle, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "awaiting_save" {
            break value;
        }
        assert!(Instant::now() < deadline, "admission was not staged");
        thread::sleep(Duration::from_millis(5));
    };
    let snapshot = bytes(&staged["snapshot"]);
    save_candidate(owner.handle, &snapshot).unwrap();
    let committed = execute_stored(owner.handle, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&committed[0]).unwrap()["members"], 2);
    commit_tx.send(()).unwrap();
    let pushed = client.join().unwrap();
    let reply: Value = serde_json::from_slice(&pushed[9..]).unwrap();
    assert!(reply["welcome"].is_array());
    assert!(reply["commit"].is_array() || reply["commits"].is_array());
    close(owner.handle).unwrap();
}

#[test]
fn tampered_and_replayed_admission_pushes_are_rejected() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(59);
    let joiner = create(Some(&[60; 32])).unwrap();
    let joiner_dir = tempfile::tempdir().unwrap();
    let pending = call(
        joiner,
        json!({"op":"begin_join","invitation":owner.invitation,
            "checkpoint":owner.checkpoint,"display_name":"Push verifier","peers":[owner.peer]}),
    )
    .unwrap();
    let workspace: [u8; 32] = bytes(&pending["workspace"]).try_into().unwrap();
    enable_record_storage(
        joiner,
        &joiner_dir.path().join("joiner.db"),
        &[60; 32],
    )
    .unwrap();
    call(
        joiner,
        json!({"op":"add_address_hint","peer":owner.peer,"address":owner.address.to_string()}),
    )
    .unwrap();
    let joiner_info: Value = serde_json::from_str(&describe(joiner).unwrap()).unwrap();
    let joiner_peer: [u8; 32] = bytes(&joiner_info["endpoint_key"]).try_into().unwrap();
    let joiner_address = joiner_info["bound_address"]
        .as_str()
        .unwrap()
        .replace("0.0.0.0:", "127.0.0.1:");
    let staged = call(
        owner.handle,
        json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],
            "request":pending["admission_request"]}),
    )
    .unwrap();
    save_candidate(owner.handle, &bytes(&staged["snapshot"])).unwrap();
    execute_stored(owner.handle, br#"{"op":"adopt_admission"}"#, &bytes(&staged["snapshot"]))
        .unwrap();
    let reply = call(
        owner.handle,
        json!({"op":"retained_admission","authenticated_endpoint":pending["endpoint"],
            "request":pending["admission_request"]}),
    )
    .unwrap();
    let mut tampered = reply.clone();
    let mut welcome = bytes(&tampered["welcome"]);
    welcome[0] ^= 1;
    tampered["welcome"] = json!(welcome);

    let send = |packet: Vec<u8>| {
        let address = joiner_address.clone();
        thread::spawn(move || {
            call(
                owner.handle,
                json!({"op":"control_exchange","peer":joiner_peer,
                    "address":address,"payload":packet}),
            )
        })
    };
    let tampered_exchange = send(admission_result_packet(&tampered));
    assert!(wait_for_work(joiner).unwrap());
    let rejected = call(joiner, json!({"op":"drive_join"})).unwrap();
    assert_eq!(rejected["state"], "admission_unavailable");
    assert_eq!(rejected["reason"], "invalid_admission_offer");
    assert_eq!(tampered_exchange.join().unwrap().unwrap()["reply"], json!([0]));

    let valid_exchange = send(admission_result_packet(&reply));
    assert!(wait_for_work(joiner).unwrap());
    let candidate = call(joiner, json!({"op":"drive_join"})).unwrap();
    assert_eq!(candidate["state"], "awaiting_join_save");
    save_candidate(joiner, &bytes(&candidate["snapshot"])).unwrap();
    let joined_bytes = execute_stored(
        joiner,
        br#"{"op":"adopt_join"}"#,
        &bytes(&candidate["snapshot"]),
    )
    .unwrap();
    let joined: Value = serde_json::from_slice(&joined_bytes[0]).unwrap();
    assert_eq!(joined["members"], 2);
    assert_eq!(valid_exchange.join().unwrap().unwrap()["reply"], json!([1]));

    let replay_exchange = send(admission_result_packet(&reply));
    assert!(wait_for_work(joiner).unwrap());
    let replayed = call(joiner, json!({"op":"drive_join"})).unwrap();
    assert_eq!(replayed["state"], "admission_unavailable");
    assert_eq!(replayed["reason"], "unrecognized_admission_pusher");
    assert_eq!(replay_exchange.join().unwrap().unwrap()["reply"], json!([0]));

    close(joiner).unwrap();
    close(owner.handle).unwrap();
    let joined_workspace: [u8; 32] = bytes(&joined["workspace"]).try_into().unwrap();
    assert_eq!(workspace, joined_workspace);
}

#[test]
fn a_sent_request_with_no_reply_reports_waiting_not_an_error() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(53);
    let late = create(Some(&[54; 32])).unwrap();
    let begun = call(
        late,
        json!({"op":"begin_join","invitation":owner.invitation,
            "checkpoint":owner.checkpoint,"display_name":"Patient joiner"}),
    )
    .unwrap();
    assert!(begun["admission_request"].is_array());
    call(
        late,
        json!({"op":"add_address_hint","peer":owner.peer,"address":owner.address.to_string()}),
    )
    .unwrap();

    // The owner never calls poll_admission: sent, never answered.
    let reply = call(late, json!({"op":"request_admission","peer":owner.peer})).unwrap();
    assert_eq!(reply["state"], "admission_waiting", "{reply}");

    close(late).unwrap();
    close(owner.handle).unwrap();
}

/// A control request that arrives while an admission commit is pending is set
/// aside (admission intake keeps its order). When the commit lands, the host
/// must be woken for it: nothing else will arrive to wake it, and before this
/// fix only the 250 ms backup tick found it (tablet HEWN: a recovery request,
/// no signal in the preceding second, 2026-09-18).
#[test]
fn a_request_set_aside_during_a_commit_wakes_the_host_when_the_commit_lands() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(55);
    let (peer, address) = (owner.peer, owner.address);
    let (invitation, checkpoint) = (owner.invitation.clone(), owner.checkpoint.clone());
    let (send_recovery, recovery_now) = std::sync::mpsc::channel::<()>();
    let clients = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let shadow = Owner { handle: 0, peer, address, invitation, checkpoint, _dir: tempfile::tempdir().unwrap() };
            let (node, packet) = joiner(5500, &shadow).await;
            let admission = tokio::spawn({
                let node = Arc::clone(&node);
                async move { node.request_control(peer, &packet).await }
            });
            tokio::task::spawn_blocking(move || recovery_now.recv().unwrap()).await.unwrap();
            let (other, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            other.add_address_hint(peer, address).await.unwrap();
            let _ = other.request_control(peer, b"DFHQ not a real range query").await;
            let _ = admission.await;
        })
    });

    // Stage the admission and keep it pending: the owner is now busy.
    let deadline = Instant::now() + Duration::from_secs(20);
    let staged = loop {
        assert!(Instant::now() < deadline, "the admission never staged");
        let value = call(owner.handle, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "awaiting_save" {
            break value;
        }
        thread::sleep(Duration::from_millis(5));
    };
    // Count wakes from here on.
    let (woke, wakes) = std::sync::mpsc::channel();
    let handle = owner.handle;
    thread::spawn(move || {
        while wait_for_work(handle).unwrap_or(false) {
            if woke.send(()).is_err() {
                break;
            }
        }
    });
    send_recovery.send(()).unwrap();
    // The recovery request arrives and is set aside while the commit is pending.
    wakes.recv_timeout(Duration::from_secs(10)).expect("the recovery request never arrived");
    thread::sleep(Duration::from_millis(200));
    assert!(call(owner.handle, json!({"op":"poll_admission"})).unwrap().is_null(),
        "a pending commit must set the recovery request aside");
    while wakes.try_recv().is_ok() {}

    let snapshot = bytes(&staged["snapshot"]);
    save_candidate(owner.handle, &snapshot).unwrap();
    execute_stored(owner.handle, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap();
    let woken = wakes.recv_timeout(Duration::from_secs(1));
    let served = drive(owner.handle, Instant::now() + Duration::from_secs(5), |value| value["state"] == "recovery_replied");
    close(owner.handle).unwrap();
    clients.join().unwrap();

    assert!(woken.is_ok(), "the commit landed but the host was not woken for the request set aside");
    assert!(served, "the request set aside was never served");
}

/// Requests already waiting when the owner reads are one group commit, not one
/// commit each: staging waits until no admission packet is waiting (or a
/// batch's worth of reads), so six waiting joiners land in the first commit.
/// Found by mutation testing: forcing `should_stage_queued_admission` to true
/// passed every other test.
#[test]
fn waiting_requests_are_one_group_commit() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let owner = owner(56);
    let (peer, address) = (owner.peer, owner.address);
    let (invitation, checkpoint) = (owner.invitation.clone(), owner.checkpoint.clone());
    let clients = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        runtime.block_on(async move {
            let shadow = Owner { handle: 0, peer, address, invitation, checkpoint, _dir: tempfile::tempdir().unwrap() };
            let mut tasks = tokio::task::JoinSet::new();
            for index in 0..6u64 {
                let (node, packet) = joiner(5600 + index, &shadow).await;
                tasks.spawn(async move { node.request_control(peer, &packet).await });
            }
            while tasks.join_next().await.is_some() {}
        })
    });
    // Test code may sleep: let every request land before the owner reads.
    thread::sleep(Duration::from_secs(3));
    let mut first_commit = None;
    drive(owner.handle, Instant::now() + Duration::from_secs(20), |value| {
        if first_commit.is_none() && value["state"] == "awaiting_save" {
            first_commit = Some(value["admissions"].as_u64().unwrap_or(0));
        }
        clients.is_finished()
    });
    clients.join().unwrap();
    close(owner.handle).unwrap();
    assert_eq!(first_commit, Some(6), "the six waiting joiners were not one commit");
}
