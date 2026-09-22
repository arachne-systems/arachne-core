use arachne_runtime::{
    close, create, describe, enable_record_storage, execute, execute_stored, save_candidate,
};
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// The runtime allows 8 nodes per process; these tests each use several.
static NODES: Mutex<()> = Mutex::new(());

fn call(handle: i64, request: Value) -> Value {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap()).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    value.as_array().unwrap().iter().map(|byte| byte.as_u64().unwrap() as u8).collect()
}

fn hint(from: i64, to: i64) {
    let info: Value = serde_json::from_str(&describe(to).unwrap()).unwrap();
    call(from, json!({"op":"add_address_hint","peer":info["endpoint_key"],
        "address":info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}));
}

/// A member at epoch N must receive the owner's step to N+1 by gossip, with no
/// pull. Before ADR 0008 the overlay dropped any envelope from another policy
/// revision, so behind members learned of new members only by polling peers
/// one at a time (12-141 s lag on tablets, 2026-09-18).
#[test]
fn a_committed_step_reaches_a_member_by_gossip_across_the_epoch() {
    let _nodes = NODES.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[94; 32])).unwrap();
    let member = create(Some(&[95; 32])).unwrap();
    let late = create(Some(&[96; 32])).unwrap();
    call(admin, json!({"op":"create_workspace","display_name":"Coordinator"}));
    let invite = call(admin, json!({"op":"issue_invitation"}));
    let begin = |handle, name| call(handle, json!({"op":"begin_join","invitation":invite["invitation"],
        "checkpoint":invite["checkpoint"],"display_name":name}));
    let admit = |joiner: &Value| {
        let staged = call(admin, json!({"op":"stage_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}));
        call(admin, json!({"op":"adopt_admission","snapshot":staged["snapshot"]}));
        call(admin, json!({"op":"retained_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}))
    };
    let early = begin(member, "Member");
    let reply = admit(&early);
    let staged = call(member, json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}));
    call(member, json!({"op":"adopt_join","snapshot":staged["snapshot"]}));
    hint(admin, member);
    hint(member, admin);
    for handle in [admin, member] {
        call(handle, json!({"op":"install_workspace_policy","revision":2}));
    }
    // Let the two overlays find each other before the commit.
    std::thread::sleep(Duration::from_millis(1500));

    // Two commits back to back: the member is then two steps behind and must
    // apply them in order, from gossip alone.
    let later = create(Some(&[97; 32])).unwrap();
    admit(&begin(late, "Late"));
    admit(&begin(later, "Later"));

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut members = 2;
    while members < 4 {
        assert!(Instant::now() < deadline, "the member reached {members} of 4 members by gossip");
        // The author serves the range pull when its host drains controls.
        call(admin, json!({"op":"poll_admission"}));
        let staged = call(member, json!({"op":"poll_admission"}));
        if staged["state"] != "awaiting_save" {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        assert_eq!(staged["gossip"], true, "{staged}");
        let snapshot = bytes(&staged["snapshot"]);
        save_candidate(member, &snapshot).unwrap_or(());
        let adopted: Value = serde_json::from_slice(
            &execute_stored(member, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap()[0]).unwrap();
        assert_eq!(adopted["members"], members + 1, "steps applied out of order: {adopted}");
        members += 1;
    }
    let sent = call(admin, json!({"op":"workspace_metrics"}))["membership_gossip"].clone();
    assert_eq!(sent["sent"], 2, "{sent}");
    let received = call(member, json!({"op":"workspace_metrics"}))["membership_gossip"].clone();
    assert_eq!(received["staged"], 2, "{received}");
    assert_eq!(received["rejected"], 0, "{received}");
    for handle in [admin, member, late, later] {
        close(handle).unwrap();
    }
}

/// The Android host installs the new epoch's policy after every commit, on the
/// owner and on each member. That must not break the swarm: on tablets the
/// owner's sends failed (3 of 5) and a member stopped at 3 of 53 members while
/// every epoch change rebuilt the overlay from scratch (2026-09-18).
#[test]
fn steps_keep_arriving_while_every_epoch_reinstalls_policy() {
    let _nodes = NODES.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[98; 32])).unwrap();
    let member = create(Some(&[99; 32])).unwrap();
    call(admin, json!({"op":"create_workspace","display_name":"Coordinator"}));
    // As the Android host does at creation: the admin's overlay starts with no
    // other member (tablet HEWN then skipped every broadcast: sent 0).
    call(admin, json!({"op":"install_workspace_policy","revision":1}));
    let invite = call(admin, json!({"op":"issue_invitation"}));
    let begin = |handle: i64, name: &str| call(handle, json!({"op":"begin_join","invitation":invite["invitation"],
        "checkpoint":invite["checkpoint"],"display_name":name}));
    let admit = |joiner: &Value| {
        let staged = call(admin, json!({"op":"stage_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}));
        let adopted = call(admin, json!({"op":"adopt_admission","snapshot":staged["snapshot"]}));
        // As the Android host does after every commit.
        call(admin, json!({"op":"install_workspace_policy","revision":adopted["epoch"].as_u64().unwrap() + 1}));
        call(admin, json!({"op":"retained_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}))
    };
    let reply = admit(&begin(member, "Member"));
    let staged = call(member, json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}));
    call(member, json!({"op":"adopt_join","snapshot":staged["snapshot"]}));
    // As on tablets: the member knows the admin's address, not the reverse.
    hint(member, admin);
    call(member, json!({"op":"install_workspace_policy","revision":2}));
    std::thread::sleep(Duration::from_millis(1500));

    // Each joiner only supplies a request; its node closes once admitted.
    for index in 0..5u8 {
        let handle = create(Some(&[100 + index; 32])).unwrap();
        let name = format!("Joiner {index}");
        let joiner = begin(handle, &name);
        admit(&joiner);
        close(handle).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut members = 2;
    while members < 7 {
        assert!(Instant::now() < deadline, "the member reached {members} of 7 members by gossip");
        // The author serves the range pull when its host drains controls.
        call(admin, json!({"op":"poll_admission"}));
        let staged = call(member, json!({"op":"poll_admission"}));
        if staged["state"] != "awaiting_save" {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let snapshot = bytes(&staged["snapshot"]);
        save_candidate(member, &snapshot).unwrap_or(());
        let adopted: Value = serde_json::from_slice(
            &execute_stored(member, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap()[0]).unwrap();
        members = adopted["members"].as_u64().unwrap();
        // As the Android host does after every epoch change.
        call(member, json!({"op":"install_workspace_policy","revision":adopted["epoch"].as_u64().unwrap() + 1}));
    }
    let sent = call(admin, json!({"op":"workspace_metrics"}))["membership_gossip"].clone();
    assert!(sent["sent"].as_u64().unwrap() >= 5, "the admin did not send its steps: {sent}");
    for handle in [admin, member] {
        close(handle).unwrap();
    }
}

/// A new member's name reaches existing members by gossip. Names used to
/// travel only two at a time in replies to membership queries; once steps
/// arrived by gossip, members queried less and showed 6 of 53 names on
/// tablets (2026-09-18). A profile is signed by its member, so a receiver
/// verifies it against its own roster exactly as a pulled one.
#[test]
fn a_new_members_name_reaches_existing_members_by_gossip() {
    let _nodes = NODES.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[110; 32])).unwrap();
    let member = create(Some(&[111; 32])).unwrap();
    let late = create(Some(&[112; 32])).unwrap();
    call(admin, json!({"op":"create_workspace","display_name":"Coordinator"}));
    let invite = call(admin, json!({"op":"issue_invitation"}));
    let join = |handle: i64, name: &str| {
        // A fresh invitation each time: its checkpoint is the current epoch, so
        // the joiner needs only its own commit.
        let fresh = call(admin, json!({"op":"issue_invitation"}));
        let pending = call(handle, json!({"op":"begin_join","invitation":fresh["invitation"],
            "checkpoint":fresh["checkpoint"],"display_name":name}));
        let staged = call(admin, json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],
            "request":pending["admission_request"]}));
        let adopted = call(admin, json!({"op":"adopt_admission","snapshot":staged["snapshot"]}));
        call(admin, json!({"op":"install_workspace_policy","revision":adopted["epoch"].as_u64().unwrap() + 1}));
        call(admin, json!({"op":"retained_admission","authenticated_endpoint":pending["endpoint"],
            "request":pending["admission_request"]}))
    };
    let reply = join(member, "Member");
    let staged = call(member, json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}));
    call(member, json!({"op":"adopt_join","snapshot":staged["snapshot"]}));
    hint(admin, member);
    hint(member, admin);
    call(member, json!({"op":"install_workspace_policy","revision":2}));
    std::thread::sleep(Duration::from_millis(1500));

    // The late member joins; the existing member takes the step by gossip.
    let reply = join(late, "Late member");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "the member did not take the step by gossip");
        call(admin, json!({"op":"poll_admission"}));
        let staged = call(member, json!({"op":"poll_admission"}));
        if staged["state"] == "awaiting_save" {
            let snapshot = bytes(&staged["snapshot"]);
            save_candidate(member, &snapshot).unwrap_or(());
            let adopted: Value = serde_json::from_slice(
                &execute_stored(member, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap()[0]).unwrap();
            call(member, json!({"op":"install_workspace_policy","revision":adopted["epoch"].as_u64().unwrap() + 1}));
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // The late member finishes joining and sends its name to the admin only.
    let staged = call(late, json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}));
    call(late, json!({"op":"adopt_join","snapshot":staged["snapshot"]}));
    hint(late, admin);
    call(late, json!({"op":"fetch_membership_update","peer":invite["peer"]}));
    let deadline = Instant::now() + Duration::from_secs(10);
    while call(late, json!({"op":"poll_membership_update"})).is_null() {
        assert!(Instant::now() < deadline, "the late member's query never completed");
        call(admin, json!({"op":"poll_admission"}));
        std::thread::sleep(Duration::from_millis(10));
    }
    // The existing member never queries; the name must arrive by gossip.
    // The admin's committed view answered the query without its host
    // (ADR 0010); the name leaves on the host's next poll, which the work
    // signal wakes on a device.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        call(admin, json!({"op":"poll_admission"}));
        call(member, json!({"op":"poll_admission"}));
        let roster = call(member, json!({"op":"member_roster"}));
        if roster["members"].as_array().unwrap().iter().any(|m| m["display_name"] == "Late member") {
            break;
        }
        assert!(Instant::now() < deadline, "the new member's name did not reach the existing member: {roster}");
        std::thread::sleep(Duration::from_millis(20));
    }
    for handle in [admin, member, late] {
        close(handle).unwrap();
    }
}

/// A gossiped step that arrived early is held until the epoch before it lands.
/// Its arrival signal was spent then, so landing that epoch must wake the host
/// again, or the held step waits for the 250 ms backup tick (tablets: JOSA and
/// BIG RED, a held epoch-8 step picked up by the backup tick, 2026-09-18).
#[test]
fn a_held_step_wakes_the_host_when_its_turn_comes() {
    let _nodes = NODES.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[120; 32])).unwrap();
    let member = create(Some(&[121; 32])).unwrap();
    let late = create(Some(&[122; 32])).unwrap();
    let later = create(Some(&[123; 32])).unwrap();
    call(admin, json!({"op":"create_workspace","display_name":"Coordinator"}));
    call(admin, json!({"op":"install_workspace_policy","revision":1}));
    let invite = call(admin, json!({"op":"issue_invitation"}));
    let begin = |handle: i64, name: &str| call(handle, json!({"op":"begin_join","invitation":invite["invitation"],
        "checkpoint":invite["checkpoint"],"display_name":name}));
    let admit = |joiner: &Value| {
        let staged = call(admin, json!({"op":"stage_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}));
        let adopted = call(admin, json!({"op":"adopt_admission","snapshot":staged["snapshot"]}));
        call(admin, json!({"op":"install_workspace_policy","revision":adopted["epoch"].as_u64().unwrap() + 1}));
        call(admin, json!({"op":"retained_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}))
    };
    let reply = admit(&begin(member, "Member"));
    let staged = call(member, json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}));
    call(member, json!({"op":"adopt_join","snapshot":staged["snapshot"]}));
    hint(member, admin);
    call(member, json!({"op":"install_workspace_policy","revision":2}));
    std::thread::sleep(Duration::from_millis(1500));
    // Two commits: both steps reach the member; the second waits for the first.
    admit(&begin(late, "Late"));
    admit(&begin(later, "Later"));
    std::thread::sleep(Duration::from_millis(1000));

    let (woke, wakes) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        while arachne_runtime::wait_for_work(member).unwrap_or(false) {
            if woke.send(()).is_err() { break; }
        }
    });
    // Take the first step; the second stays held.
    let staged = loop {
        call(admin, json!({"op":"poll_admission"}));
        let value = call(member, json!({"op":"poll_admission"}));
        if value["state"] == "awaiting_save" { break value; }
        std::thread::sleep(Duration::from_millis(10));
    };
    std::thread::sleep(Duration::from_millis(200));
    while wakes.try_recv().is_ok() {}
    let snapshot = bytes(&staged["snapshot"]);
    save_candidate(member, &snapshot).unwrap_or(());
    execute_stored(member, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap();
    // Nothing new arrives; only landing the epoch can wake the host now.
    let woken = wakes.recv_timeout(Duration::from_secs(1));
    let held = call(member, json!({"op":"poll_admission"}));
    for handle in [admin, member, late, later] {
        close(handle).unwrap();
    }
    assert_eq!(held["state"], "awaiting_save", "the held step was not ready: {held}");
    assert!(woken.is_ok(), "the held step became ready but the host was not woken");
}

/// A member that missed several steps must catch up from the next head it
/// hears, in one exchange with the author. Before ADR 0009 gossip carried full
/// steps: a member that missed one held every later step and waited for the
/// slow roster pull (tablet BIG RED held epochs 7-8 for 47 s, 2026-09-18).
#[test]
fn a_member_that_missed_steps_catches_up_from_the_next_head() {
    let _nodes = NODES.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[130; 32])).unwrap();
    let member = create(Some(&[131; 32])).unwrap();
    call(admin, json!({"op":"create_workspace","display_name":"Coordinator"}));
    call(admin, json!({"op":"install_workspace_policy","revision":1}));
    let invite = call(admin, json!({"op":"issue_invitation"}));
    let begin = |handle: i64, name: &str| call(handle, json!({"op":"begin_join","invitation":invite["invitation"],
        "checkpoint":invite["checkpoint"],"display_name":name}));
    let admit = |joiner: &Value| {
        let staged = call(admin, json!({"op":"stage_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}));
        let adopted = call(admin, json!({"op":"adopt_admission","snapshot":staged["snapshot"]}));
        call(admin, json!({"op":"install_workspace_policy","revision":adopted["epoch"].as_u64().unwrap() + 1}));
        call(admin, json!({"op":"retained_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}))
    };
    let reply = admit(&begin(member, "Member"));
    let staged = call(member, json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}));
    let joined = call(member, json!({"op":"adopt_join","snapshot":staged["snapshot"]}));
    hint(member, admin);
    // Three commits while the member has no overlay: it misses all three.
    for index in 0..3u8 {
        let handle = create(Some(&[132 + index; 32])).unwrap();
        admit(&begin(handle, &format!("Missed {index}")));
        close(handle).unwrap();
    }
    // A send waits up to 2 s for a first neighbor; let those sends give up.
    std::thread::sleep(Duration::from_millis(2500));
    call(member, json!({"op":"install_workspace_policy","revision":joined["epoch"].as_u64().unwrap() + 1}));
    std::thread::sleep(Duration::from_millis(1500));
    // One more commit. Its announcement is the only thing the member hears.
    let last = create(Some(&[135; 32])).unwrap();
    admit(&begin(last, "Last"));
    close(last).unwrap();

    let started = Instant::now();
    let mut members = joined["members"].as_u64().unwrap();
    while members < 6 {
        assert!(started.elapsed() < Duration::from_secs(5), "the member reached {members} of 6 members");
        // The author serves the range pull when its host drains controls.
        call(admin, json!({"op":"poll_admission"}));
        let staged = call(member, json!({"op":"poll_admission"}));
        if staged["state"] != "awaiting_save" {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let snapshot = bytes(&staged["snapshot"]);
        save_candidate(member, &snapshot).unwrap_or(());
        let adopted: Value = serde_json::from_slice(
            &execute_stored(member, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap()[0]).unwrap();
        members = adopted["members"].as_u64().unwrap();
        call(member, json!({"op":"install_workspace_policy","revision":adopted["epoch"].as_u64().unwrap() + 1}));
    }
    // One announcement and one exchange carried all four missing steps.
    let counts = call(member, json!({"op":"workspace_metrics"}))["membership_gossip"].clone();
    assert_eq!(counts["range_pulled"], 1, "{counts}");
    assert_eq!(counts["staged"], 4, "{counts}");
    // Having reached the head, the member announces it once, so members
    // behind it can pull from it instead of the owner.
    let deadline = Instant::now() + Duration::from_secs(3);
    while call(member, json!({"op":"workspace_metrics"}))["membership_gossip"]["sent"] != 1 {
        assert!(Instant::now() < deadline, "the member did not announce the head it reached");
        std::thread::sleep(Duration::from_millis(20));
    }
    for handle in [admin, member] {
        close(handle).unwrap();
    }
}

/// Presence alone must start the range pull: a member with no overlay that
/// hears a newer epoch in a presence reply catches up in one exchange, not
/// one step per 5 s roster query (ADR 0009).
#[test]
fn presence_of_a_newer_epoch_starts_the_range_pull() {
    let _nodes = NODES.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[140; 32])).unwrap();
    let member = create(Some(&[141; 32])).unwrap();
    call(admin, json!({"op":"create_workspace","display_name":"Coordinator"}));
    let invite = call(admin, json!({"op":"issue_invitation"}));
    let begin = |handle: i64, name: &str| call(handle, json!({"op":"begin_join","invitation":invite["invitation"],
        "checkpoint":invite["checkpoint"],"display_name":name}));
    let admit = |joiner: &Value| {
        let staged = call(admin, json!({"op":"stage_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}));
        call(admin, json!({"op":"adopt_admission","snapshot":staged["snapshot"]}));
        call(admin, json!({"op":"retained_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}))
    };
    let reply = admit(&begin(member, "Member"));
    let staged = call(member, json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}));
    let joined = call(member, json!({"op":"adopt_join","snapshot":staged["snapshot"]}));
    hint(member, admin);
    for index in 0..3u8 {
        let handle = create(Some(&[142 + index; 32])).unwrap();
        admit(&begin(handle, &format!("Missed {index}")));
        close(handle).unwrap();
    }

    let started = Instant::now();
    let mut members = joined["members"].as_u64().unwrap();
    while members < 5 {
        assert!(started.elapsed() < Duration::from_secs(5), "the member reached {members} of 5 members");
        call(member, json!({"op":"poll_workspace_presence","announce":false}));
        call(admin, json!({"op":"poll_admission"}));
        let staged = call(member, json!({"op":"poll_admission"}));
        if staged["state"] != "awaiting_save" {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let snapshot = bytes(&staged["snapshot"]);
        save_candidate(member, &snapshot).unwrap_or(());
        let adopted: Value = serde_json::from_slice(
            &execute_stored(member, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap()[0]).unwrap();
        members = adopted["members"].as_u64().unwrap();
    }
    let counts = call(member, json!({"op":"workspace_metrics"}))["membership_gossip"].clone();
    assert_eq!(counts["received"], 0, "no gossip reached the member: {counts}");
    assert_eq!(counts["range_pulled"], 1, "{counts}");
    for handle in [admin, member] {
        close(handle).unwrap();
    }
}

/// Asking a member that is behind is not a membership conflict. The owner's
/// roster pull asked BIG RED, then at epoch 4 of 8; its "unavailable" reply
/// raised "Membership differs from a connected peer" on HEWN (fix16c,
/// 2026-09-19). The peer is only behind, and the range pull catches it up.
#[test]
fn a_peer_that_is_behind_is_reported_as_behind_not_as_a_conflict() {
    let _nodes = NODES.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[150; 32])).unwrap();
    let member = create(Some(&[151; 32])).unwrap();
    call(admin, json!({"op":"create_workspace","display_name":"Coordinator"}));
    let invite = call(admin, json!({"op":"issue_invitation"}));
    let begin = |handle: i64, name: &str| call(handle, json!({"op":"begin_join","invitation":invite["invitation"],
        "checkpoint":invite["checkpoint"],"display_name":name}));
    let admit = |joiner: &Value| {
        let staged = call(admin, json!({"op":"stage_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}));
        call(admin, json!({"op":"adopt_admission","snapshot":staged["snapshot"]}));
        call(admin, json!({"op":"retained_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}))
    };
    let reply = admit(&begin(member, "Member"));
    let staged = call(member, json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}));
    call(member, json!({"op":"adopt_join","snapshot":staged["snapshot"]}));
    hint(admin, member);
    let later = create(Some(&[152; 32])).unwrap();
    admit(&begin(later, "Later"));
    close(later).unwrap();

    let peer: Value = serde_json::from_str(&describe(member).unwrap()).unwrap();
    call(admin, json!({"op":"fetch_membership_update","peer":peer["endpoint_key"]}));
    let deadline = Instant::now() + Duration::from_secs(10);
    let result = loop {
        call(member, json!({"op":"poll_admission"}));
        let result = call(admin, json!({"op":"poll_membership_update"}));
        if !result.is_null() { break result; }
        assert!(Instant::now() < deadline, "the query never completed");
        std::thread::sleep(Duration::from_millis(10));
    };
    for handle in [admin, member] {
        close(handle).unwrap();
    }
    assert_eq!(result["state"], "membership_peer_behind", "{result}");
}

/// The range pull is an inquiry (ADR 0010): the owner answers it from its
/// committed view, so a member catches up while the owner's host is busy and
/// never polls its control queue.
#[test]
fn a_range_pull_is_answered_while_the_owner_host_never_polls() {
    let _nodes = NODES.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[160; 32])).unwrap();
    let member = create(Some(&[161; 32])).unwrap();
    call(admin, json!({"op":"create_workspace","display_name":"Coordinator"}));
    call(admin, json!({"op":"install_workspace_policy","revision":1}));
    let invite = call(admin, json!({"op":"issue_invitation"}));
    let begin = |handle: i64, name: &str| call(handle, json!({"op":"begin_join","invitation":invite["invitation"],
        "checkpoint":invite["checkpoint"],"display_name":name}));
    let admit = |joiner: &Value| {
        let staged = call(admin, json!({"op":"stage_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}));
        let adopted = call(admin, json!({"op":"adopt_admission","snapshot":staged["snapshot"]}));
        call(admin, json!({"op":"install_workspace_policy","revision":adopted["epoch"].as_u64().unwrap() + 1}));
        call(admin, json!({"op":"retained_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}))
    };
    let reply = admit(&begin(member, "Member"));
    let staged = call(member, json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}));
    let joined = call(member, json!({"op":"adopt_join","snapshot":staged["snapshot"]}));
    hint(member, admin);
    // Three commits while the member has no overlay: it misses all three.
    for index in 0..3u8 {
        let handle = create(Some(&[162 + index; 32])).unwrap();
        admit(&begin(handle, &format!("Missed {index}")));
        close(handle).unwrap();
    }
    // A send waits up to 2 s for a first neighbor; let those sends give up.
    std::thread::sleep(Duration::from_millis(2500));
    call(member, json!({"op":"install_workspace_policy","revision":joined["epoch"].as_u64().unwrap() + 1}));
    std::thread::sleep(Duration::from_millis(1500));
    // One more commit. Its announcement is the only thing the member hears.
    let last = create(Some(&[165; 32])).unwrap();
    admit(&begin(last, "Last"));
    close(last).unwrap();

    let started = Instant::now();
    let mut members = joined["members"].as_u64().unwrap();
    while members < 6 {
        assert!(started.elapsed() < Duration::from_secs(5), "the member reached {members} of 6 members");
        let staged = call(member, json!({"op":"poll_admission"}));
        if staged["state"] != "awaiting_save" {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let snapshot = bytes(&staged["snapshot"]);
        save_candidate(member, &snapshot).unwrap_or(());
        let adopted: Value = serde_json::from_slice(
            &execute_stored(member, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap()[0]).unwrap();
        members = adopted["members"].as_u64().unwrap();
        call(member, json!({"op":"install_workspace_policy","revision":adopted["epoch"].as_u64().unwrap() + 1}));
    }
    // One announcement and one exchange carried all four missing steps.
    let counts = call(member, json!({"op":"workspace_metrics"}))["membership_gossip"].clone();
    assert_eq!(counts["range_pulled"], 1, "{counts}");
    assert_eq!(counts["staged"], 4, "{counts}");
    for handle in [admin, member] {
        close(handle).unwrap();
    }
}

/// A record-backed owner must serve a member catch-up across several bounded
/// range replies; replaying the whole accepted history per step stalls this.
#[test]
fn a_member_catches_up_after_a_large_admission_wave() {
    let _nodes = NODES.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create(Some(&[170; 32])).unwrap();
    let member = create(Some(&[171; 32])).unwrap();
    call(admin, json!({"op":"create_workspace","display_name":"Coordinator"}));
    let directory = tempfile::tempdir().unwrap();
    enable_record_storage(admin, &directory.path().join("admin.db"), &[170; 32]).unwrap();
    call(admin, json!({"op":"install_workspace_policy","revision":1}));
    let invite = call(admin, json!({"op":"issue_invitation"}));
    let begin = |handle: i64, name: &str| call(handle, json!({"op":"begin_join","invitation":invite["invitation"],
        "checkpoint":invite["checkpoint"],"display_name":name}));
    let admit = |joiner: &Value| {
        let staged = call(admin, json!({"op":"stage_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}));
        let snapshot = bytes(&staged["snapshot"]);
        save_candidate(admin, &snapshot).unwrap();
        let adopted: Value = serde_json::from_slice(
            &execute_stored(admin, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap()[0]).unwrap();
        call(admin, json!({"op":"install_workspace_policy","revision":adopted["epoch"].as_u64().unwrap() + 1}));
        call(admin, json!({"op":"retained_admission","authenticated_endpoint":joiner["endpoint"],
            "request":joiner["admission_request"]}))
    };
    let pending = begin(member, "Member");
    enable_record_storage(member, &directory.path().join("member.db"), &[171; 32]).unwrap();
    let reply = admit(&pending);
    let staged = call(member, json!({"op":"stage_join","welcome":reply["welcome"],
        "commits":[{"commit":reply["commit"],"authorization":reply["authorization"]}]}));
    let snapshot = bytes(&staged["snapshot"]);
    save_candidate(member, &snapshot).unwrap();
    let joined: Value = serde_json::from_slice(
        &execute_stored(member, br#"{"op":"adopt_join"}"#, &snapshot).unwrap()[0]).unwrap();
    hint(member, admin);
    call(member, json!({"op":"install_workspace_policy","revision":joined["epoch"].as_u64().unwrap() + 1}));
    std::thread::sleep(Duration::from_millis(1500));

    for index in 0..80u8 {
        let handle = create(Some(&[20 + index; 32])).unwrap();
        admit(&begin(handle, &format!("Missed {index}")));
        close(handle).unwrap();
    }

    let peer: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
    call(member, json!({"op":"fetch_membership_update","peer":peer["endpoint_key"]}));
    let query_deadline = Instant::now() + Duration::from_secs(10);
    let query = loop {
        let query = call(member, json!({"op":"poll_membership_update"}));
        if !query.is_null() {
            break query;
        }
        assert!(Instant::now() < query_deadline, "membership query did not complete");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(query["state"], "membership_update_available");
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut members = joined["members"].as_u64().unwrap();
    while members < 82 {
        let staged = call(member, json!({"op":"poll_admission"}));
        assert!(Instant::now() < deadline,
            "catch-up stopped at {members} members; last={staged}; metrics={}",
            call(member, json!({"op":"workspace_metrics"})));
        if staged["state"] != "awaiting_save" {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let snapshot = bytes(&staged["snapshot"]);
        save_candidate(member, &snapshot).unwrap_or(());
        let adopted: Value = serde_json::from_slice(
            &execute_stored(member, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap()[0]).unwrap();
        members = adopted["members"].as_u64().unwrap();
        call(member, json!({"op":"install_workspace_policy","revision":adopted["epoch"].as_u64().unwrap() + 1}));
    }
    assert_eq!(members, 82);
    let counts = call(member, json!({"op":"workspace_metrics"}))["membership_gossip"].clone();
    assert_eq!(counts["rejected"], 0, "catch-up rejected a membership step: {counts}");
    assert!(
        counts["range_pulled"].as_u64().unwrap() >= 3,
        "80 missed steps should require at least three range pages: {counts}"
    );
    for handle in [admin, member] {
        close(handle).unwrap();
    }
}
