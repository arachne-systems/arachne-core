// FUT-28: an invitation issued at epoch 0 must stay redeemable after the
// workspace has accumulated far more than 64 membership epochs.
//
// The pinned checkpoint digest inside the signed grant never moves, so a
// joiner redeeming an old invitation has to verify every transition from that
// checkpoint to the current epoch. Three ceilings used to stop that at 64
// steps:
//
//   * `JoinProof::appended_history` refused the 65th step, because the inline
//     `DFJH` blob it maintains is capped at 64 steps,
//   * `StageJoin` refused more than 64 commits in one call
//     (`lib.rs` around the `StageJoin` dispatch), and
//   * the `request_admission` page loop refused more than 64 pages.
//
// The fix is rollover, not a bigger constant: the joiner's verified state
// rolls forward chunk by chunk while every individual encoding, request and
// page keeps obeying the same 64-step / 128 KiB bounds it always did.
//
// These tests build a real 100+ epoch workspace with local management
// transitions (no network per epoch), then redeem the epoch-0 invitation over
// real Iroh endpoints so the byte-bounded paging path is exercised.

use arachne_node::MAX_CONTROL_REPLY;
use arachne_runtime::{close, create, describe, enable_record_storage, execute, save_candidate};
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// 55 promote/demote cycles on top of the helper's own admission puts the
/// workspace far past the 64-step ceiling without a network round trip each.
const RAMP_CYCLES: usize = 55;

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

/// Honour the durable-save-before-ack contract on sessions that keep records;
/// sessions without record storage simply have nothing to commit.
fn adopt(handle: i64, op: &str, staged: &Value) -> Value {
    let _ = save_candidate(handle, &bytes(&staged["snapshot"]));
    call(handle, json!({"op":op,"snapshot":staged["snapshot"]})).unwrap()
}

fn node(handle: i64) -> Value {
    serde_json::from_str(&describe(handle).unwrap()).unwrap()
}

fn loopback(value: &Value) -> String {
    value["bound_address"]
        .as_str()
        .unwrap()
        .replace("0.0.0.0:", "127.0.0.1:")
}

fn hint(handle: i64, peer: &Value, address: &str) {
    call(
        handle,
        json!({"op":"add_address_hint","peer":peer,"address":address}),
    )
    .unwrap();
}

/// Pull exactly one authenticated membership step from `responder` into
/// `receiver` and adopt it. Both ends stay real Iroh endpoints; polling is
/// test scheduling only.
fn sync_one(responder: i64, receiver: i64, peer: &Value) -> Value {
    call(
        receiver,
        json!({"op":"fetch_membership_update","peer":peer}),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let step = loop {
        call(responder, json!({"op":"poll_admission"})).unwrap();
        let value = call(receiver, json!({"op":"poll_membership_update"})).unwrap();
        if value != Value::Null {
            assert_eq!(value["state"], "membership_update_available");
            break value["step"].clone();
        }
        assert!(Instant::now() < deadline, "membership update timed out");
        std::thread::sleep(Duration::from_millis(5));
    };
    let staged = call(receiver, json!({"op":"stage_admission_update","step":step})).unwrap();
    adopt(receiver, "adopt_admission", &staged)
}

struct Ramp {
    admin: i64,
    helper: i64,
    invite: Value,
    late: i64,
    /// Total membership transitions between the pinned epoch-0 checkpoint and
    /// the workspace's current epoch.
    steps: u64,
    dirs: Vec<tempfile::TempDir>,
    seed: u8,
}

/// Build a workspace whose history is far longer than the 64-step ceiling,
/// with one ordinary member fully synchronised to the head epoch.
fn ramp(seed: u8) -> Ramp {
    let admin = create(Some(&[seed; 32])).unwrap();
    let helper = create(Some(&[seed + 1; 32])).unwrap();
    let late = create(Some(&[seed + 2; 32])).unwrap();
    let dirs: Vec<tempfile::TempDir> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    call(
        admin,
        json!({"op":"create_workspace","display_name":"Coordinator"}),
    )
    .unwrap();
    enable_record_storage(admin, &dirs[0].path().join("admin.db"), &[seed; 32]).unwrap();
    let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();

    // The helper joins at the very beginning, so its own retained history is
    // anchored at the same epoch-0 checkpoint the late joiner pins.
    let early = call(
        helper,
        json!({"op":"begin_join","invitation":invite["invitation"],
            "checkpoint":invite["checkpoint"],"display_name":"Available member"}),
    )
    .unwrap();
    let staged = call(
        admin,
        json!({"op":"stage_admission","authenticated_endpoint":early["endpoint"],
            "request":early["admission_request"]}),
    )
    .unwrap();
    adopt(admin, "adopt_admission", &staged);
    let reply = call(
        admin,
        json!({"op":"retained_admission","authenticated_endpoint":early["endpoint"],
            "request":early["admission_request"]}),
    )
    .unwrap();
    let staged = call(
        helper,
        json!({"op":"stage_join","welcome":reply["welcome"],
            "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}),
    )
    .unwrap();
    adopt(helper, "adopt_join", &staged);
    enable_record_storage(helper, &dirs[1].path().join("helper.db"), &[seed + 1; 32]).unwrap();

    let member = early["member"]["id"].clone();
    for _ in 0..RAMP_CYCLES {
        for kind in ["promote", "demote"] {
            let change = call(
                admin,
                json!({"op":"stage_management","action":{"kind":kind,"member":member}}),
            )
            .unwrap();
            adopt(admin, "adopt_admission", &change);
        }
    }
    let steps = 1 + 2 * RAMP_CYCLES as u64;
    assert!(
        steps > 64,
        "the scenario must exceed the 64-step ceiling it is about to test"
    );

    let admin_node = node(admin);
    let helper_node = node(helper);
    hint(helper, &admin_node["endpoint_key"], &loopback(&admin_node));
    hint(admin, &helper_node["endpoint_key"], &loopback(&helper_node));
    let mut current = Value::Null;
    for _ in 0..(steps - 1) {
        current = sync_one(admin, helper, &admin_node["endpoint_key"]);
    }
    assert_eq!(
        current["epoch"],
        json!(steps),
        "the ordinary member must be current before it serves an old invitation"
    );

    Ramp {
        admin,
        helper,
        invite,
        late,
        steps,
        dirs,
        seed,
    }
}

/// Drive the responder's control inbox until the joiner's call returns,
/// adopting any transition it stages. Polling is test scheduling; the real
/// host polls on its own cadence.
fn pump<T>(responder: i64, worker: &std::thread::JoinHandle<T>, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(300);
    while !worker.is_finished() {
        let event = call(responder, json!({"op":"poll_admission"})).unwrap();
        if event["state"] == "awaiting_save" {
            adopt(responder, "adopt_admission", &event);
        }
        assert!(Instant::now() < deadline, "{message}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Redeem the epoch-0 invitation against `responder` and return the staged
/// reply, asserting every served page stayed inside the control-reply bound.
fn redeem(ramp: &Ramp, responder: i64, responder_peer: Value) -> Value {
    let responder_node = node(responder);
    hint(
        ramp.late,
        &responder_node["endpoint_key"],
        &loopback(&responder_node),
    );
    call(
        ramp.late,
        json!({"op":"begin_join","invitation":ramp.invite["invitation"],
            "checkpoint":ramp.invite["checkpoint"],"display_name":"Late arrival"}),
    )
    .unwrap();
    // A 100+ epoch history is far past the 128 KiB sealed-snapshot budget, so
    // the joiner keeps records like any real member would. That budget is a
    // separate, unchanged byte bound (FUT-33), not the step ceiling under test.
    enable_record_storage(
        ramp.late,
        &ramp.dirs[2].path().join("late.db"),
        &[ramp.seed + 2; 32],
    )
    .unwrap();

    let late = ramp.late;
    let peer = responder_peer;

    // First attempt: the responder stages, saves and adopts the Add.
    let queueing = {
        let peer = peer.clone();
        std::thread::spawn(move || call(late, json!({"op":"request_admission","peer":peer})))
    };
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let event = call(responder, json!({"op":"poll_admission"})).unwrap();
        if event["state"] == "awaiting_save" {
            adopt(responder, "adopt_admission", &event);
            break;
        }
        assert!(Instant::now() < deadline, "responder never staged the join");
        std::thread::sleep(Duration::from_millis(5));
    }
    // The owner holds the request's exchange and writes the result onto it
    // after save and adopt (event-driven admission), so the first request
    // carries the retained reply, paged over as many control replies as the
    // rolled-over history needs. Keep serving pages until it completes.
    pump(responder, &queueing, "responder never served the join history");
    let reply = queueing.join().unwrap().expect("old invitation must redeem");

    let carried = reply["commits"]
        .as_array()
        .expect("complete authorized history")
        .len();
    let rolled = reply["history_verified_prefix"].as_u64().unwrap_or(0);
    assert!(
        carried <= 64,
        "the host must still carry at most one 64-step chunk, not {carried}"
    );
    assert!(
        rolled > 0,
        "a 100+ epoch history must roll over instead of arriving in one chunk"
    );
    assert!(
        rolled + carried as u64 >= ramp.steps,
        "history must cover every epoch since the pinned checkpoint: {rolled} + {carried} < {}",
        ramp.steps
    );
    let pages = reply["history_page_bytes"]
        .as_array()
        .expect("the joiner must report the size of every page it accepted");
    assert!(
        pages.len() > 1,
        "a 100+ epoch history must be served as more than one page"
    );
    let mut total = 0usize;
    for page in pages {
        let bytes = page.as_u64().unwrap() as usize;
        assert!(
            bytes <= MAX_CONTROL_REPLY,
            "served page of {bytes} bytes exceeds the {MAX_CONTROL_REPLY} byte control-reply bound"
        );
        total += bytes;
    }
    // The whole exchange is bounded too, not just each page: a responder is a
    // reachable member, not a trusted one.
    assert!(
        total <= arachne_security::MAX_JOIN_HISTORY_BYTES,
        "paged history of {total} bytes exceeds the whole-exchange bound"
    );
    reply
}

#[test]
fn epoch_zero_invitation_redeems_through_the_issuer_after_a_hundred_epochs() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let ramp = ramp(171);
    let peer = ramp.invite["peer"].clone();
    let reply = redeem(&ramp, ramp.admin, peer);

    let staged = call(
        ramp.late,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":reply["commits"]}),
    )
    .expect("a joiner must be able to verify more than 64 steps of history");
    let joined = adopt(ramp.late, "adopt_join", &staged);
    assert_eq!(joined["epoch"], json!(ramp.steps + 1));

    close(ramp.late).unwrap();
    close(ramp.helper).unwrap();
    close(ramp.admin).unwrap();
}

#[test]
fn epoch_zero_invitation_redeems_through_an_ordinary_member_with_the_issuer_offline() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let ramp = ramp(181);
    let helper_peer = node(ramp.helper)["endpoint_key"].clone();
    close(ramp.admin).unwrap();
    assert!(describe(ramp.admin).is_err());

    let reply = redeem(&ramp, ramp.helper, helper_peer);

    // A stale rolled-over anchor must not bypass verification: a history that
    // skips its first step no longer chains from the pinned checkpoint.
    let mut truncated = reply["commits"].as_array().unwrap().clone();
    truncated.remove(0);
    assert!(
        call(
            ramp.late,
            json!({"op":"stage_join","welcome":reply["welcome"],"commits":truncated})
        )
        .is_err(),
        "a truncated history must be rejected, however long the accepted one was"
    );
    let mut tampered = reply["commits"].as_array().unwrap().clone();
    let last = tampered.len() - 1;
    let byte = tampered[last]["commit"][0].as_u64().unwrap() ^ 1;
    tampered[last]["commit"][0] = json!(byte);
    assert!(
        call(
            ramp.late,
            json!({"op":"stage_join","welcome":reply["welcome"],"commits":tampered})
        )
        .is_err(),
        "a tampered commit must be rejected after rollover, not only before it"
    );

    let staged = call(
        ramp.late,
        json!({"op":"stage_join","welcome":reply["welcome"],"commits":reply["commits"]}),
    )
    .expect("an ordinary member must serve the full authorized history");
    let joined = adopt(ramp.late, "adopt_join", &staged);
    assert_eq!(joined["epoch"], json!(ramp.steps + 1));

    close(ramp.late).unwrap();
    close(ramp.helper).unwrap();
}
