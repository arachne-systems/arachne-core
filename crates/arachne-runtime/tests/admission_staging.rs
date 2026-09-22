// FUT-31: owner-side admission batch staging must keep committing while
// admission packets keep arriving. Before the fix, `PollAdmission` only
// attempted to stage a queued batch on a tick that found no incoming
// control packet (`lib.rs` around the poll-tick dispatch). Under continuous
// intake -- new admission packets arriving on effectively every tick, as
// FUT-30 retry traffic produces at scale -- that tick is (almost) never
// empty, so staging starves indefinitely and queued joiners never reach a
// retained reply.
//
// The continuous intake here is exactly the mechanism the issue's own
// evidence names: "Joiners today retry every 0.5-5 s (FUT-30), keeping the
// inbox non-empty." All 64 requests below retry on that cadence for as long
// as they remain unadmitted, which is enough on its own to keep the owner's
// control inbox non-empty on (almost) every poll tick -- no separate cohort
// of brand-new joiners is needed to reproduce the starvation.
//
// Completion is measured owner-side (committed batch sizes summing to all
// 64, cross-checked against the final member roster), not by waiting for
// each of the 64 clients to individually observe a retained reply over the
// wire. AC-84's "reach reply-retained" is a workspace-side state (the
// retained admission lives in `workspace.admissions` the moment a batch is
// adopted); requiring a further network round trip per joiner would fold in
// `queue_admission`'s retained-reply path, which re-verifies the full
// accumulated commit history per request and is a separate, pre-existing
// crypto cost unrelated to the scheduling bug this test targets.
//
// This test asserts that:
//   - all 64 requests are committed (staged, saved and adopted) within a
//     fixed bound (this is the part that times out on unfixed code),
//   - intake-accepted and batch-committed counters both advance -- the
//     batch-committed counter never goes more than a bounded number of
//     consecutive seconds without progress while intake keeps growing, and
//   - committed batch sizes reach the cap of 16, and have median >= 5 as
//     an INTERIM bar. FUT-31's real requirement is median >= 8; it is
//     DEFERRED, not replaced, to #91 (FUT-35), which is scoped to restore
//     the >= 8 assertion once its root cause (a pre-existing, out-of-scope
//     arachne-security cost, not a scheduling one) is bounded. See the
//     assertion below for the measurements behind this deferral.

use arachne_node::Node;
use arachne_runtime::{
    close, create, describe, enable_record_storage, execute, execute_stored,
    restore_record_storage, save_candidate,
};
use arachne_security::{Invitation, PendingJoin};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// A member node bound and ready to send its admission packet.
struct Joiner {
    node: Arc<Node>,
    packet: Vec<u8>,
}

/// Send one admission packet and drive the owner's poll loop until the owner
/// handles it. Returns the cost of the owner-side tick that handled it -- the
/// tick that pays for checkpoint preflight -- and that tick's poll value.
fn timed_admission(
    owner: i64,
    joiner: Joiner,
    owner_peer: [u8; 32],
    owner_address: SocketAddr,
) -> (Duration, Value) {
    let Joiner { node, packet } = joiner;
    let sending = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            node.add_address_hint(owner_peer, owner_address).await.ok();
            let deadline = Instant::now() + Duration::from_secs(90);
            while Instant::now() < deadline {
                if node.request_control(owner_peer, &packet).await.is_ok() {
                    return;
                }
            }
            panic!("admission packet never reached the owner");
        })
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut handled: Option<(Duration, Value)> = None;
    while handled.is_none() {
        assert!(
            Instant::now() < deadline,
            "owner never handled the extra admission"
        );
        let tick = Instant::now();
        let value = call(owner, json!({"op":"poll_admission","profile":true})).unwrap();
        match value["state"].as_str() {
            Some("admission_queued") if value["intake"] == json!(true) => {
                handled = Some((tick.elapsed(), value));
            }
            Some("admission_replied") => handled = Some((tick.elapsed(), value)),
            Some("awaiting_save") => {
                let snapshot = bytes(&value["snapshot"]);
                save_candidate(owner, &snapshot).unwrap();
                execute_stored(owner, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap();
            }
            _ => {}
        }
        thread::sleep(Duration::from_millis(5));
    }
    // Keep servicing the inbox so the sender's request gets its reply.
    let drain = Instant::now() + Duration::from_secs(90);
    while !sending.is_finished() {
        assert!(Instant::now() < drain, "extra joiner never got a reply");
        let value = call(owner, json!({"op":"poll_admission","profile":true})).unwrap();
        if value["state"] == "awaiting_save" {
            let snapshot = bytes(&value["snapshot"]);
            save_candidate(owner, &snapshot).unwrap();
            execute_stored(owner, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap();
        }
        thread::sleep(Duration::from_millis(5));
    }
    sending.join().unwrap();
    handled.unwrap()
}

/// Bind a joiner whose packet pins `pinned` rather than the checkpoint its
/// pending join was built from, so a tampered chain can be presented.
async fn bind_joiner_with(
    seed_index: u64,
    invitation: &Invitation,
    checkpoint: &[u8],
    pinned: &[u8],
) -> Joiner {
    let mut joiner = bind_joiner(seed_index, invitation, checkpoint).await;
    let request_len = joiner.packet.len() - checkpoint.len();
    joiner.packet.truncate(request_len);
    joiner.packet.extend_from_slice(pinned);
    joiner
}

async fn bind_joiner(seed_index: u64, invitation: &Invitation, checkpoint: &[u8]) -> Joiner {
    let mut seed = [0; 32];
    seed[..8].copy_from_slice(&seed_index.to_be_bytes());
    let (node, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &seed)
        .await
        .unwrap();
    let node = Arc::new(node);
    let peer = node.id();
    let pending = PendingJoin::from_invitation(invitation, checkpoint, peer, "Staging member")
        .unwrap();
    let packet = admission_packet(
        pending.admission_request().unwrap(),
        "Staging member",
        checkpoint,
    );
    Joiner { node, packet }
}

#[test]
fn admission_batch_staging_keeps_committing_under_continuous_intake() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    const PRIORITY: usize = 64;
    // FUT-30's own field behavior: joiners retry every 0.5-5s. 500ms is the
    // fast end of that real range. The owner's poll loop below is paced to
    // the real host tick (WorkspaceController.kt:246, 250ms/PollAdmission
    // call) rather than run unthrottled -- an earlier, unpaced version of
    // this test let the owner's poll loop outrun arrivals and find gaps
    // even old (buggy) code could stage through, which is not what
    // production does: the host only calls PollAdmission once per 250ms,
    // so "no incoming this tick" only happens when nothing arrived in that
    // whole interval. At 128 requests/s combined (64 joiners x 2/s) against
    // 4 ticks/s, gaps should not occur.
    const PRIORITY_RETRY_INTERVAL: Duration = Duration::from_millis(500);
    // The host tick this owner's poll loop is paced to, matching
    // WorkspaceController.kt:246 (also cited in the issue's evidence).
    const HOST_POLL_TICK: Duration = Duration::from_millis(250);
    // Generous: draining 64 admissions one per 250ms host tick is a floor
    // of ~16s by itself; admission crypto (KeyPackage/authorization
    // validation, and the retained-reply history preflight) both scale
    // with the owner's accumulated commit history, and MLS commit cost
    // scales with group size -- both can run into seconds per operation on
    // a loaded box (observed multiple seconds per commit, and a full
    // unpaced run around 107-127s, in this environment). This bound is
    // about proving the scheduler makes forward progress, not enforcing a
    // latency SLA.
    const COMPLETION_BOUND: Duration = Duration::from_secs(180);

    let started = Instant::now();
    let owner = create(Some(&[31; 32])).unwrap();
    call(
        owner,
        json!({"op":"create_workspace","display_name":"Staging owner","workspace_name":"FUT-31 staging"}),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    enable_record_storage(owner, &dir.path().join("owner.db"), &[31; 32]).unwrap();
    // FUT-35: the link is created through the registered `stage_invitation`
    // path the plugin itself uses (WorkspaceController's create-link flow),
    // not the bare `issue_invitation` helper. Registration is what makes the
    // owner retain the checkpoint the link pins, and that retained checkpoint
    // is what lets admission preflight stop re-verifying the owner's own
    // accepted branch for every arriving request. Every assertion in this test
    // is unchanged; only how the link is created differs.
    let staged = call(
        owner,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    )
    .unwrap();
    save_candidate(owner, &bytes(&staged["snapshot"])).unwrap();
    let invitation = call(
        owner,
        json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
    )
    .unwrap()["issued_invitation"]
        .clone();
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

    // Kept out of the client thread so the restart and tampered-chain cases
    // below can bind their own joiners against the same link.
    let extra_invitation = invitation_bytes.clone();
    let extra_checkpoint = checkpoint.clone();

    let stop_retries = Arc::new(AtomicBool::new(false));
    let stop_retries_client = Arc::clone(&stop_retries);
    let overall_deadline = Instant::now() + COMPLETION_BOUND + Duration::from_secs(60);

    let client_thread = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let invitation = Invitation::from_bytes(&invitation_bytes).unwrap();

            let mut priority = Vec::with_capacity(PRIORITY);
            for index in 0..PRIORITY {
                priority.push(bind_joiner(1000 + index as u64, &invitation, &checkpoint).await);
            }

            // Send the initial admission packet for each of the 64 and
            // confirm it lands in the owner's queue. The owner's poll loop
            // runs concurrently on the main test thread from the moment
            // this client thread is spawned, so these sends are serviced
            // as they arrive rather than deadlocking on a not-yet-polling
            // owner. A busy owner occasionally misses the 30s control
            // deadline on any one connection; that is backpressure, not a
            // failure, so each send retries rather than failing outright.
            let mut initial: JoinSet<()> = JoinSet::new();
            for joiner in &priority {
                let node = Arc::clone(&joiner.node);
                let packet = joiner.packet.clone();
                initial.spawn(async move {
                    node.add_address_hint(owner_peer, owner_address).await.ok();
                    loop {
                        assert!(
                            Instant::now() < overall_deadline,
                            "initial admission send never got a reply"
                        );
                        let Ok(reply) = node.request_control(owner_peer, &packet).await else {
                            continue;
                        };
                        let value: Value = serde_json::from_slice(&reply).unwrap();
                        // A retry here (after a lost/timed-out reply to a
                        // send that the owner actually processed) can land
                        // after the request was already staged and
                        // retained -- that is also success, just observed
                        // late, not a failure.
                        assert!(
                            value["state"] == "admission_queued" || value["commit"].is_array(),
                            "unexpected initial admission reply: {value}"
                        );
                        return;
                    }
                });
            }
            while let Some(result) = initial.join_next().await {
                result.unwrap();
            }

            // Retry every priority joiner on FUT-30's cadence. This retry
            // traffic is itself the continuous intake under test -- it is
            // exactly what keeps the owner's inbox non-empty in the field.
            // Completion is measured owner-side (see the main thread's
            // loop below), so these tasks just keep the intake going until
            // told to stop; they don't gate the test's pass condition.
            let mut retry: JoinSet<()> = JoinSet::new();
            for joiner in priority {
                let stop_retries = Arc::clone(&stop_retries_client);
                retry.spawn(async move {
                    while !stop_retries.load(Ordering::Relaxed) {
                        if Instant::now() >= overall_deadline {
                            return;
                        }
                        let Ok(reply) =
                            joiner.node.request_control(owner_peer, &joiner.packet).await
                        else {
                            continue;
                        };
                        let value: Value = serde_json::from_slice(&reply).unwrap();
                        if value["state"] != "admission_queued" {
                            // Retained: nothing further to do for this joiner.
                            return;
                        }
                        tokio::time::sleep(PRIORITY_RETRY_INTERVAL).await;
                    }
                });
            }
            while let Some(result) = retry.join_next().await {
                result.unwrap();
            }
        })
    });

    // Drive the owner's poll loop immediately -- the client thread's
    // initial sends above are network calls that only complete once this
    // loop is polling to service them. Record batch sizes and intake/commit
    // progress timestamps while the priority cohort's admissions commit.
    let mut batch_sizes: Vec<usize> = Vec::new();
    let mut intake_events: Vec<Instant> = Vec::new();
    // FUT-35: owner-side cost of the poll tick that newly accepted an
    // admission -- the tick that pays for checkpoint preflight. A retry of an
    // already-queued request short-circuits long before that and is not
    // counted, which is why `queue_admission` marks the accepting tick.
    let mut intake_costs: Vec<Duration> = Vec::new();
    let mut commit_events: Vec<Instant> = Vec::new();
    let deadline = Instant::now() + COMPLETION_BOUND;

    loop {
        let committed: usize = batch_sizes.iter().sum();
        if committed >= PRIORITY {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "FUT-31 regression: admission batch staging starved under continuous \
             intake -- only {committed}/{PRIORITY} priority requests committed \
             within {COMPLETION_BOUND:?} (batches so far: {batch_sizes:?})"
        );
        let tick_started = Instant::now();
        let value = call(owner, json!({"op":"poll_admission","profile":true})).unwrap();
        match value["state"].as_str() {
            Some("awaiting_save") => {
                let count = value["admissions"].as_u64().unwrap() as usize;
                let snapshot = bytes(&value["snapshot"]);
                save_candidate(owner, &snapshot).unwrap();
                execute_stored(owner, br#"{"op":"adopt_admission"}"#, &snapshot).unwrap();
                batch_sizes.push(count);
                commit_events.push(Instant::now());
            }
            Some("admission_queued") => {
                intake_events.push(Instant::now());
                if value["intake"] == json!(true) {
                    intake_costs.push(tick_started.elapsed());
                }
            }
            Some("approval_requested") => {
                panic!("open invitation unexpectedly requested approval: {value}");
            }
            _ => {}
        }
        // Pace this loop to the real host tick: the production poller only
        // calls PollAdmission once per 250ms (WorkspaceController.kt:246),
        // so "no incoming this tick" only ever happens when nothing arrived
        // in a whole 250ms window -- not because this loop outran arrivals
        // by calling far faster than any real host does. Pad up to (not
        // past) the tick boundary; a slow stage that already exceeded it
        // does not get an extra wait tacked on.
        if let Some(remaining) = HOST_POLL_TICK.checked_sub(tick_started.elapsed()) {
            thread::sleep(remaining);
        }
    }

    let committed: usize = batch_sizes.iter().sum();
    assert_eq!(committed, PRIORITY, "committed count does not match priority count");

    let roster = call(owner, json!({"op":"member_roster"})).unwrap();
    assert_eq!(
        roster["members"].as_array().unwrap().len(),
        PRIORITY + 1,
        "final member roster does not include all 64 priority joiners plus the owner"
    );

    // All 64 are committed; stop the client's retry traffic and let it wind
    // down. Keep servicing the owner's poll loop for a bounded drain period
    // so any already-in-flight client requests get a reply rather than
    // hanging until their own connection-level timeout.
    stop_retries.store(true, Ordering::Relaxed);
    let join_deadline = Instant::now() + Duration::from_secs(45);
    while !client_thread.is_finished() {
        assert!(
            Instant::now() < join_deadline,
            "client thread did not finish after retries were told to stop"
        );
        let _ = call(owner, json!({"op":"poll_admission"}));
        thread::sleep(Duration::from_millis(5));
    }
    client_thread.join().unwrap();

    // --- Acceptance checks -------------------------------------------------

    assert!(
        !batch_sizes.is_empty(),
        "no admission batches were ever staged"
    );

    let mut sorted = batch_sizes.clone();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2];
    let max = *sorted.last().unwrap();
    // FUT-31's requirement is median >= 8, restored here by FUT-35. It was
    // previously deferred to an interim >= 5 because queue_admission's
    // checkpoint preflight re-verified the owner's *entire* accumulated commit
    // history on every newly-arriving admission (~65ms/item early in a run,
    // ~400ms+/item once a few dozen members in), which throttled how many
    // admissions could accumulate before the cadence/cap fired. With the
    // preflight bounded (see the intake-cost assertion below), scheduling is
    // free to fill batches again.
    assert!(
        median >= 8,
        "expected median committed batch size >= 8, got {median} \
         (batches: {batch_sizes:?}, intake costs: {intake_costs:?})"
    );
    assert_eq!(
        max, 16,
        "expected max committed batch size to reach the 16 cap, got {max} (batches: {batch_sizes:?})"
    );

    // FUT-35: per-admission intake cost must not grow with the accumulated
    // commit history. A single tick is noisy at these magnitudes, so each end
    // is the median of a five-sample window centred on the named admission --
    // the same claim as "the 60th costs at most twice the 5th", measured in a
    // way one scheduler hiccup cannot decide.
    assert!(
        intake_costs.len() >= 62,
        "expected at least 62 newly-accepted admissions to measure, got {} \
         (costs: {intake_costs:?})",
        intake_costs.len()
    );
    let window = |centre: usize| -> Duration {
        let mut sample: Vec<Duration> = intake_costs[centre - 3..centre + 2].to_vec();
        sample.sort_unstable();
        sample[sample.len() / 2]
    };
    let early = window(5);
    let late = window(60);
    assert!(
        late <= early * 2,
        "FUT-35 regression: per-admission intake cost grows with commit history \
         -- 60th admission {late:?} exceeds 2x the 5th ({early:?}); \
         costs: {intake_costs:?}"
    );

    // FUT-35: a tampered chain must still be refused. The checkpoint an
    // admission pins is the one the cheap path keys on, so a request pinning a
    // tampered checkpoint is exactly the attempt that must not be waved
    // through by a preflight that no longer replays every commit.
    let extras = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut tampered_checkpoint = extra_checkpoint.clone();
    *tampered_checkpoint.last_mut().unwrap() ^= 1;
    let invitation_value = Invitation::from_bytes(&extra_invitation).unwrap();
    let tampered = extras.block_on(bind_joiner_with(
        7000,
        &invitation_value,
        &extra_checkpoint,
        &tampered_checkpoint,
    ));
    let (_, refused) = timed_admission(owner, tampered, owner_peer, owner_address);
    assert_eq!(
        refused["state"], "admission_replied",
        "a tampered checkpoint must be answered, not queued: {refused}"
    );
    assert_eq!(
        refused["accepted"], false,
        "a tampered checkpoint must be refused: {refused}"
    );
    let roster = call(owner, json!({"op":"member_roster"})).unwrap();
    assert_eq!(
        roster["members"].as_array().unwrap().len(),
        PRIORITY + 1,
        "a refused tampered chain must not add a member"
    );

    // FUT-35: the bound must survive a restart. The owner's retained
    // invitation checkpoint is durable, so a restarted owner keeps the cheap
    // preflight instead of paying full-history re-verification again.
    close(owner).unwrap();
    let owner = create(Some(&[31; 32])).unwrap();
    let workspace: [u8; 32] = endpoint(&invitation["workspace"]);
    restore_record_storage(owner, &dir.path().join("owner.db"), &[31; 32], workspace).unwrap();
    let restarted_info: Value = serde_json::from_str(&describe(owner).unwrap()).unwrap();
    let restarted_peer = endpoint(&restarted_info["endpoint_key"]);
    let restarted_port = restarted_info["bound_address"]
        .as_str()
        .unwrap()
        .rsplit_once(':')
        .unwrap()
        .1
        .parse::<u16>()
        .unwrap();
    let restarted_address = SocketAddr::from(([127, 0, 0, 1], restarted_port));
    let post_restart = extras.block_on(bind_joiner(7001, &invitation_value, &extra_checkpoint));
    let (restart_cost, accepted) =
        timed_admission(owner, post_restart, restarted_peer, restarted_address);
    assert_eq!(
        accepted["state"], "admission_queued",
        "the first post-restart admission must be accepted: {accepted}"
    );
    assert!(
        restart_cost <= early * 2,
        "FUT-35 regression: a restart reintroduced full-history re-verification \
         -- first post-restart admission cost {restart_cost:?} exceeds 2x the 5th \
         ({early:?})"
    );

    // Neither counter may stall for an extended stretch while the other
    // keeps advancing. Bucket both event streams into 1s windows relative
    // to the run start. A single MLS commit can legitimately span several
    // seconds under load (group-size-dependent crypto cost, observed up to
    // several seconds per commit in this environment) -- during that span
    // intake keeps growing with no commit yet, and that is expected, not
    // starvation. So the check is a bounded run: intake must never go more
    // than MAX_STALL_SECS consecutive seconds without a commit landing.
    // FUT-31's actual bug produced an *unbounded* stall (starvation forever
    // under continuous intake), so this still fails hard on the regression
    // while tolerating one slow commit's natural duration.
    const MAX_STALL_SECS: u64 = 25;
    let bucket = |events: &[Instant]| -> BTreeMap<u64, usize> {
        let mut buckets = BTreeMap::new();
        for event in events {
            let second = event.duration_since(started).as_secs();
            *buckets.entry(second).or_insert(0) += 1;
        }
        buckets
    };
    let intake_buckets = bucket(&intake_events);
    let commit_buckets = bucket(&commit_events);
    let last_second = intake_buckets
        .keys()
        .chain(commit_buckets.keys())
        .copied()
        .max()
        .unwrap_or(0);
    let mut current_stall = 0u64;
    let mut max_stall = 0u64;
    let mut worst_window_end = 0u64;
    for second in 0..=last_second {
        let intake = intake_buckets.get(&second).copied().unwrap_or(0);
        let commit = commit_buckets.get(&second).copied().unwrap_or(0);
        if intake > 0 && commit == 0 {
            current_stall += 1;
            if current_stall > max_stall {
                max_stall = current_stall;
                worst_window_end = second;
            }
        } else {
            current_stall = 0;
        }
    }
    assert!(
        max_stall <= MAX_STALL_SECS,
        "batch-committed counter stalled for {max_stall}s (ending at t={worst_window_end}s) \
         while intake kept growing -- exceeds the {MAX_STALL_SECS}s bound \
         (intake_buckets={intake_buckets:?}, commit_buckets={commit_buckets:?})"
    );

    println!(
        "admission_staging: priority={PRIORITY} batches={} median_batch={median} \
         max_batch={max} intake_events={} commit_events={} elapsed_ms={} \
         intake_5th={early:?} intake_60th={late:?} post_restart={restart_cost:?}",
        batch_sizes.len(),
        intake_events.len(),
        commit_events.len(),
        started.elapsed().as_millis()
    );
    close(owner).unwrap();
}
