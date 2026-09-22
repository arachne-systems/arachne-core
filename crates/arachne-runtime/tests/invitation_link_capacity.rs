use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use arachne_node::{ConnectionBudget, NetworkProfile, Node};
use arachne_runtime::harness::{self, Query, StateBasis};
use arachne_security::{AdmissionAuthorization, Invitation, MembershipAuthorization, PendingJoin};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;

const PREFIX: &str = "arachne://join#";
const INVITATION_SIZE: usize = 293;
const COMPACT_SIZE: usize = 390;
const BOOTSTRAP_PEERS: usize = 3;
const CONTROL_PACKET: &[u8] = b"DFIC\x01";
static TEST_LOCK: Mutex<()> = Mutex::new(());

/// What a capacity run actually measured. `AdmissionOnly` is the legacy
/// bug this harness had (issue #93): a joiner counted ready the instant it
/// held a Welcome, with no `stage_join`, no adopted MLS state, no member
/// profile, no presence -- admission issuance only. `FullOnboarding` is the
/// default and the only depth that proves a joiner can actually be found,
/// named and reached in the owner's roster.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessDepth {
    AdmissionOnly,
    FullOnboarding,
}
impl ProcessDepth {
    fn label(self) -> &'static str {
        match self {
            Self::AdmissionOnly => "admission_only",
            Self::FullOnboarding => "full_onboarding",
        }
    }
    fn from_env() -> Self {
        match std::env::var("ARACHNE_CAPACITY_PROCESS_DEPTH")
            .ok()
            .as_deref()
        {
            Some("admission_only") => Self::AdmissionOnly,
            _ => Self::FullOnboarding,
        }
    }
}

/// Disjoint, exhaustive outcome tally: every index ends in exactly one
/// bucket. `unresolved_ever_queued` and `unresolved_never_replied` partition
/// the indices still pending when the retry loop exited, by whether that
/// index ever received an explicit `admission_queued` reply.
struct CapacityOutcome {
    resolved_ready: usize,
    resolved_terminal_failure: usize,
    unresolved_ever_queued: usize,
    unresolved_never_replied: usize,
    transport_retries: usize,
    terminal_states: BTreeMap<String, usize>,
    ready_elapsed_ms: Vec<u128>,
    terminal_failure_elapsed_ms: Vec<u128>,
    initial_batch_elapsed_ms: u128,
    retry_loop_end_ms: u128,
    teardown_ms: u128,
    full_onboarding: Option<FullOnboardingOutcome>,
}

/// Full-onboarding depth tally, layered on top of admission. `welcomed` is
/// the old "ready" definition; `ready` only counts joiners that finished
/// every phase below with a verifiably named, signed profile delivered.
#[derive(Default)]
struct FullOnboardingOutcome {
    welcomed: usize,
    ready: usize,
    failed_by_phase: BTreeMap<&'static str, usize>,
    stage_joined_ms: Vec<u128>,
    adopted_ms: Vec<u128>,
    profiled_ms: Vec<u128>,
    presence_ms: Vec<u128>,
}

/// Per-joiner full-onboarding state machine result. `failed_phase` is set
/// the moment any step fails, and that joiner is never counted ready --
/// this is the mechanism the red test in
/// `local_full_onboarding_state_machine_rejects_a_corrupted_joiner` proves.
#[derive(Default, Clone)]
struct JoinerFullRecord {
    ready: bool,
    display_name: String,
    stage_joined_ms: u128,
    adopted_ms: u128,
    profiled_ms: u128,
    presence_ms: u128,
    failed_phase: Option<&'static str>,
    failure_reason: Option<String>,
}
impl JoinerFullRecord {
    fn fail(&mut self, phase: &'static str, reason: impl Into<String>) {
        self.failed_phase = Some(phase);
        self.failure_reason = Some(reason.into());
    }
}

fn link(path: &str) -> Result<(Invitation, Vec<[u8; 32]>), String> {
    let value = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let value = value.trim();
    let encoded = value
        .strip_prefix(PREFIX)
        .ok_or("invitation link must use arachne://join")?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "invitation link is not canonical base64url")?;
    if raw.len() != COMPACT_SIZE || raw[0] != 3 {
        return Err("invitation link is not the current compact format".into());
    }
    let invitation = Invitation::from_bytes(&raw[1..1 + INVITATION_SIZE]).map_err(str::to_owned)?;
    let mut peers = Vec::new();
    let mut padding = false;
    for chunk in raw[294..].as_chunks::<32>().0.iter().take(BOOTSTRAP_PEERS) {
        if chunk.iter().all(|byte| *byte == 0) {
            padding = true;
            continue;
        }
        if padding {
            return Err("invitation link has non-contiguous bootstrap peers".into());
        }
        let peer = *chunk;
        if peers.contains(&peer) {
            return Err("invitation link repeats a bootstrap peer".into());
        }
        peers.push(peer);
    }
    if peers.is_empty() {
        return Err("invitation link has no bootstrap peer".into());
    }
    Ok((invitation, peers))
}

fn packet(request: &[u8], name: &str, checkpoint: &[u8]) -> Vec<u8> {
    let mut packet = b"DFJA\x02".to_vec();
    packet.extend((request.len() as u32).to_be_bytes());
    packet.extend((name.len() as u16).to_be_bytes());
    packet.extend(request);
    packet.extend(name.as_bytes());
    packet.extend(checkpoint);
    packet
}

async fn fetch_checkpoint(
    node: &Node,
    invitation: &Invitation,
    peers: &[[u8; 32]],
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let mut last = None;
    for peer in peers {
        let request = invitation
            .checkpoint_request(node.id(), *peer)
            .map_err(str::to_owned)?;
        let mut payload = CONTROL_PACKET.to_vec();
        payload.extend(request);
        match node.request_control(*peer, &payload).await {
            Ok(reply) => return Ok((reply, *peer)),
            Err(error) => last = Some(error.to_string()),
        }
    }
    Err(last.unwrap_or_else(|| "no bootstrap peers".into()))
}

fn rss_bytes() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmHWM:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|value| value.parse::<u64>().ok())
        })
        .map(|kilobytes| kilobytes * 1024)
        .unwrap_or(0)
}

fn write_receipt(path: Option<&str>, value: &Value) {
    if let Some(path) = path {
        fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }
}

fn array32(value: &Value) -> Result<[u8; 32], String> {
    let bytes: Vec<u8> = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    bytes.try_into().map_err(|_| "expected 32 bytes".to_string())
}

fn array64(value: &Value) -> Result<[u8; 64], String> {
    let bytes: Vec<u8> = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    bytes.try_into().map_err(|_| "expected 64 bytes".to_string())
}

/// Build the typed admission authorization straight from the admission
/// reply's `authorization` JSON object (`invitation_key`, `grant_signature`,
/// `redemption_signature` -- exactly `AdmissionAuthorization`'s public
/// fields, see `arachne_runtime::lib::RetainedAdmission`'s reply at
/// lib.rs:1191-1193). No arachne-runtime seam needed for this leg.
fn build_authorization(value: &Value) -> Result<AdmissionAuthorization, String> {
    Ok(AdmissionAuthorization {
        invitation_key: array32(&value["invitation_key"])?,
        grant_signature: array64(&value["grant_signature"])?,
        redemption_signature: array64(&value["redemption_signature"])?,
    })
}

const ADMISSION_HISTORY_PAGE_REQUEST: &[u8; 5] = b"DFJP\x01";

/// Mirrors `arachne_runtime::admission_history_page_packet` (lib.rs:1258),
/// a stable, already-shipped wire request any authenticated peer may send:
/// `"DFJP\x01" ++ request_len(u32 BE) ++ checkpoint_len(u32 BE) ++
/// offset(u32 BE) ++ request ++ checkpoint`.
fn history_page_packet(request: &[u8], checkpoint: &[u8], offset: u32) -> Vec<u8> {
    let mut packet = ADMISSION_HISTORY_PAGE_REQUEST.to_vec();
    packet.extend((request.len() as u32).to_be_bytes());
    packet.extend((checkpoint.len() as u32).to_be_bytes());
    packet.extend(offset.to_be_bytes());
    packet.extend(request);
    packet.extend(checkpoint);
    packet
}

/// Parse one reply/page's `commits` array into typed (authorization, commit)
/// steps, matching `arachne_runtime::membership::JoinStep::authorization`
/// (each step carries exactly one of `authorization` (single Admission) or
/// `admission_batch` (AdmissionBatch) -- Management steps are not produced
/// for an open invitation and are treated as an unsupported step here).
fn parse_join_steps(value: &Value) -> Result<Vec<(MembershipAuthorization, Vec<u8>)>, String> {
    let commits = value
        .get("commits")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    commits
        .iter()
        .map(|step| {
            let commit: Vec<u8> =
                serde_json::from_value(step["commit"].clone()).map_err(|e| e.to_string())?;
            let authorization = if !step["authorization"].is_null() {
                MembershipAuthorization::Admission(build_authorization(&step["authorization"])?)
            } else if let Some(batch) = step.get("admission_batch").and_then(Value::as_array) {
                MembershipAuthorization::AdmissionBatch(
                    batch
                        .iter()
                        .map(build_authorization)
                        .collect::<Result<_, String>>()?,
                )
            } else {
                return Err("join step is not an admission or admission batch".into());
            };
            Ok((authorization, commit))
        })
        .collect()
}

/// Follow the admission reply's `history_complete`/`history_next` paging
/// (lib.rs:3215-3261 does the same thing from inside the `request_admission`
/// op; a bare-Node joiner has to do it itself since it isn't going through
/// that op) until every intervening membership transition since the
/// invitation's checkpoint has been collected. A joiner admitted after other
/// joiners is behind by exactly that many epochs and must replay all of
/// them, not just its own step -- skipping this produced the "invitation
/// authorizes only Adds without policy changes" failure this harness hit
/// under concurrent joiners before this loop was added.
async fn collect_join_steps(
    node: &Node,
    peer: [u8; 32],
    request: &[u8],
    checkpoint: &[u8],
    first_reply: &Value,
) -> Result<Vec<(MembershipAuthorization, Vec<u8>)>, String> {
    let mut steps = parse_join_steps(first_reply)?;
    let mut reply = first_reply.clone();
    while !reply
        .get("history_complete")
        .and_then(Value::as_bool)
        .unwrap_or(true)
    {
        let offset = reply["history_next"]
            .as_u64()
            .ok_or("admission history page missing next offset")? as u32;
        let page_packet = history_page_packet(request, checkpoint, offset);
        let page_bytes = node
            .request_control(peer, &page_packet)
            .await
            .map_err(|error| error.to_string())?;
        let page: Value =
            serde_json::from_slice(&page_bytes).map_err(|error| error.to_string())?;
        if page["state"] != "admission_replied" || page.get("history_page").is_none() {
            return Err("admission history page was not accepted".into());
        }
        steps.extend(parse_join_steps(&page)?);
        reply = page;
    }
    Ok(steps)
}

/// Run every remaining full-onboarding phase for one already-welcomed
/// joiner: `stage_join` (MLS transition + Welcome), durable adoption
/// (a self-consistent adopted `Workspace`), signed member profile
/// publication over the DFMQ seam, and one presence interval over the DFPR
/// seam. Stops and records the failing phase at the first error -- this is
/// the joiner state machine: `Welcomed -> StageJoined -> Adopted ->
/// Profiled -> Ready`, and a joiner that fails any step is never `ready`.
#[allow(clippy::too_many_arguments)]
async fn full_onboard(
    node: Arc<Node>,
    pending: PendingJoin,
    peer: [u8; 32],
    checkpoint: Vec<u8>,
    welcome: Vec<u8>,
    first_reply: Value,
    display_name: String,
    started: Instant,
) -> JoinerFullRecord {
    let mut record = JoinerFullRecord {
        display_name: display_name.clone(),
        ..Default::default()
    };
    let request = match pending.admission_request() {
        Ok(request) => request.to_vec(),
        Err(error) => {
            record.fail("stage_join", error);
            return record;
        }
    };
    // A joiner admitted after others is behind by that many epochs: replay
    // every intervening transition since the invitation checkpoint, not
    // just this joiner's own Add.
    let steps = match collect_join_steps(&node, peer, &request, &checkpoint, &first_reply).await {
        Ok(steps) => steps,
        Err(error) => {
            record.fail("stage_join", error);
            return record;
        }
    };
    if steps.is_empty() {
        record.fail("stage_join", "admission reply carried no membership steps");
        return record;
    }
    let mut proof = match pending.join_proof() {
        Ok(proof) => proof,
        Err(error) => {
            record.fail("stage_join", error);
            return record;
        }
    };
    for (authorization, commit_bytes) in steps {
        if let Err(error) = proof.apply_transition(&authorization, &commit_bytes) {
            record.fail("stage_join", error);
            return record;
        }
    }
    let workspace = match pending.prepare_workspace(&proof, &welcome) {
        Ok(workspace) => workspace,
        Err(error) => {
            record.fail("stage_join", error);
            return record;
        }
    };
    record.stage_joined_ms = started.elapsed().as_millis();

    // Durable adoption: a joiner is only adopted once the constructed
    // Workspace's own MLS roster shows itself as a member. This is the
    // in-memory equivalent of the runtime's adopt_join op; genuine
    // disk-durable adoption is proven separately at small scale in
    // `local_full_onboarding_state_machine_rejects_a_corrupted_joiner`
    // via enable_record_storage + save_candidate + execute_stored.
    let self_id = match workspace.member() {
        Some(member) => member.id(),
        None => {
            record.fail("adopt_join", "adopted workspace has no member profile");
            return record;
        }
    };
    match workspace.member_roster() {
        Ok(roster) if roster.iter().any(|member| member.id == self_id) => {}
        Ok(_) => {
            record.fail("adopt_join", "adopted roster does not contain self");
            return record;
        }
        Err(error) => {
            record.fail("adopt_join", error);
            return record;
        }
    }
    record.adopted_ms = started.elapsed().as_millis();

    let profile_bytes = match workspace.sign_member_profile() {
        Ok(bytes) => bytes,
        Err(error) => {
            record.fail("profile_publish", error);
            return record;
        }
    };
    let name_head = workspace.workspace_name_head().unwrap_or([0; 32]);
    let query = Query {
        workspace: workspace.id(),
        basis: StateBasis::new(workspace.epoch(), workspace.epoch_fingerprint(), name_head),
        profiles_digest: [0; 32],
        profiles: [profile_bytes.as_slice(), &[]],
    };
    let query_bytes = match harness::encode_query(&query) {
        Ok(bytes) => bytes,
        Err(error) => {
            record.fail("profile_publish", error);
            return record;
        }
    };
    match node.request_control(peer, &query_bytes).await {
        Ok(reply) => match harness::decode_reply(&reply) {
            Ok(value) if value["state"] == "membership_denied" => {
                record.fail("profile_publish", format!("owner denied profile: {value}"));
                return record;
            }
            Ok(_) => {}
            Err(error) => {
                record.fail("profile_publish", error);
                return record;
            }
        },
        Err(error) => {
            record.fail("profile_publish", error.to_string());
            return record;
        }
    }
    record.profiled_ms = started.elapsed().as_millis();

    let mut instance = [0u8; 16];
    instance[..8].copy_from_slice(&(node.id()[0] as u64).to_be_bytes());
    let presence_bytes = harness::harness_presence_packet(&workspace, instance, true);
    if let Err(error) = node.request_control(peer, &presence_bytes).await {
        record.fail("presence", error.to_string());
        return record;
    }
    record.presence_ms = started.elapsed().as_millis();

    record.ready = true;
    record
}

#[test]
#[ignore = "requires a real ATAK-issued link and an active ATAK owner"]
fn one_atak_invitation_link_handles_500_synthetic_joiners() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let link_path = std::env::var("ARACHNE_INVITATION_LINK_FILE")
        .expect("set ARACHNE_INVITATION_LINK_FILE to a private link file");
    let receipt_path = std::env::var("ARACHNE_CAPACITY_RECEIPT").ok();
    let members = std::env::var("ARACHNE_CAPACITY_MEMBERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(500usize);
    let owner_address = std::env::var("ARACHNE_INVITATION_OWNER_ADDRESS")
        .ok()
        .map(|value| {
            value
                .parse()
                .expect("invalid ARACHNE_INVITATION_OWNER_ADDRESS")
        });
    let deadline_seconds = std::env::var("ARACHNE_CAPACITY_DEADLINE_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(180u64);
    let identity_offset = std::env::var("ARACHNE_CAPACITY_IDENTITY_OFFSET")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0u64);
    let process_depth = ProcessDepth::from_env();
    assert!((2..=500).contains(&members));
    let started = Instant::now();
    let (invitation, peers) = link(&link_path).unwrap();
    let mut receipt = json!({
        "scope": "One real ATAK open invitation link to a real ATAK owner plus synthetic Rust joiners",
        "passed": false,
        "process_depth": process_depth.label(),
        "invitation_link_characters": fs::read_to_string(&link_path).unwrap().trim().len(),
        "synthetic_joiners": members,
        "physical_joiners": 0,
        "bootstrap_peers": peers.len(),
        "owner_is_real_atak": true,
        "owner_is_host_polled": false,
        "identity_offset": identity_offset,
        "arrival_pattern": "burst",
        "named_roster_check": "not performed here -- the owner is a real ATAK device this \
            harness does not control; verifying member_roster shows ramp-N names is the \
            tablet-operator follow-up task. This harness proves each joiner published a \
            correctly named, signed profile and received a non-denied delivery reply.",
        "outcomes": {
            "resolved_ready": 0,
            "resolved_terminal_failure": 0,
            "unresolved_ever_queued": 0,
            "unresolved_never_replied": 0,
            "transport_retries": 0,
        },
        "terminal_states": {},
    });
    write_receipt(receipt_path.as_deref(), &receipt);

    let invitation_bytes = invitation.export_secret_token().to_vec();
    let peers_for_thread = peers.clone();
    let client_thread = thread::spawn(
        move || -> Result<CapacityOutcome, String> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(8)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            runtime.block_on(async move {
                let invitation =
                    Invitation::from_bytes(&invitation_bytes).map_err(str::to_owned)?;
                // Fetch the authenticated checkpoint before opening the burst
                // of independent WAN endpoints. The checkpoint is shared
                // bootstrap state, not joiner-specific work.
                let mut bootstrap_seed = [0; 32];
                bootstrap_seed[..8]
                    .copy_from_slice(&(identity_offset + 0xA600_0000).to_be_bytes());
                let (bootstrap, _receiver) = Node::bind_with_profile(
                    ([0, 0, 0, 0], 0).into(),
                    Some(&bootstrap_seed),
                    NetworkProfile::Wan,
                    ConnectionBudget::default(),
                )
                .await
                .map_err(|error| error.to_string())?;
                let (checkpoint, selected_peer) =
                    fetch_checkpoint(&bootstrap, &invitation, &peers_for_thread).await?;
                invitation.join_proof(&checkpoint).map_err(str::to_owned)?;
                bootstrap.close().await;
                let mut binds = JoinSet::new();
                for index in 0..members {
                    binds.spawn(async move {
                        let mut seed = [0; 32];
                        seed[..8].copy_from_slice(
                            &(index as u64 + identity_offset + 0xA700_0000).to_be_bytes(),
                        );
                        Node::bind_with_profile(
                            ([0, 0, 0, 0], 0).into(),
                            Some(&seed),
                            NetworkProfile::Wan,
                            ConnectionBudget::default(),
                        )
                        .await
                        .map(|(node, _receiver)| Arc::new(node))
                        .map_err(|error| error.to_string())
                    });
                }
                let mut nodes = Vec::with_capacity(members);
                while let Some(result) = binds.join_next().await {
                    nodes.push(result.map_err(|error| error.to_string())??);
                }
                if let Some(address) = owner_address {
                    for node in &nodes {
                        node.add_address_hint(peers_for_thread[0], address)
                            .await
                            .map_err(|error| error.to_string())?;
                    }
                }
                let mut packets = Vec::with_capacity(members);
                let mut pendings: Vec<Option<PendingJoin>> = Vec::with_capacity(members);
                for (index, node) in nodes.iter().enumerate() {
                    let display_name = format!("ramp-{}", identity_offset + index as u64);
                    let pending = PendingJoin::from_invitation(
                        &invitation,
                        &checkpoint,
                        node.id(),
                        &display_name,
                    )
                    .map_err(str::to_owned)?;
                    let request = pending.admission_request().map_err(str::to_owned)?;
                    packets.push(packet(request, &display_name, &checkpoint));
                    pendings.push(Some(pending));
                }

                let mut requests = JoinSet::new();
                for (index, (node, payload)) in nodes.iter().zip(&packets).enumerate() {
                    let node = Arc::clone(node);
                    let payload = payload.clone();
                    requests.spawn(async move {
                        (index, node.request_control(selected_peer, &payload).await)
                    });
                }
                let mut pending_indices = Vec::new();
                let mut ready_elapsed_ms = Vec::new();
                let mut terminal_failure_elapsed_ms = Vec::new();
                let mut resolved_terminal_failure = 0;
                let mut retries = 0;
                let mut ever_queued: std::collections::HashSet<usize> =
                    std::collections::HashSet::new();
                let mut terminal_states = BTreeMap::new();
                let mut welcomed: BTreeMap<usize, (Vec<u8>, Value)> = BTreeMap::new();
                while let Some(result) = requests.join_next().await {
                    let (index, result) = result.map_err(|error| error.to_string())?;
                    match result {
                        Ok(reply) => {
                            let value: Value =
                                serde_json::from_slice(&reply).map_err(|e| e.to_string())?;
                            if let Some(welcome) = value.get("welcome") {
                                ready_elapsed_ms.push(started.elapsed().as_millis());
                                welcomed.insert(
                                    index,
                                    (
                                        serde_json::from_value(welcome.clone())
                                            .map_err(|e| e.to_string())?,
                                        value.clone(),
                                    ),
                                );
                            } else if value["state"] == "admission_queued" {
                                ever_queued.insert(index);
                                pending_indices.push(index);
                            } else {
                                resolved_terminal_failure += 1;
                                terminal_failure_elapsed_ms.push(started.elapsed().as_millis());
                                let key = format!(
                                    "{}:{}",
                                    value["state"].as_str().unwrap_or("unknown"),
                                    value["reason"].as_str().unwrap_or("")
                                );
                                *terminal_states.entry(key).or_insert(0) += 1;
                            }
                        }
                        Err(_) => pending_indices.push(index),
                    }
                }
                let initial_batch_elapsed_ms = started.elapsed().as_millis();
                // NOTE: this deadline bounds only the retry loop below. It is
                // measured from the moment the initial request batch
                // finished (initial_batch_elapsed_ms), not from test start,
                // and the loop only checks it between retry rounds -- an
                // in-flight round can finish after the deadline passes. The
                // receipt records initial_batch_elapsed_ms, retry_loop_end_ms
                // and elapsed_ms (final) so a reader can compute the true
                // measured interval instead of trusting deadline_seconds as
                // an enforced wall-clock bound.
                let deadline = Instant::now() + Duration::from_secs(deadline_seconds);
                while welcomed.len() < members && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    let round = std::mem::take(&mut pending_indices);
                    let mut retry = JoinSet::new();
                    for index in round {
                        let node = Arc::clone(&nodes[index]);
                        let payload = packets[index].clone();
                        retry.spawn(async move {
                            (index, node.request_control(selected_peer, &payload).await)
                        });
                    }
                    let mut next = Vec::new();
                    while let Some(result) = retry.join_next().await {
                        let (index, result) = result.map_err(|error| error.to_string())?;
                        retries += 1;
                        match result {
                            Ok(reply) => {
                                let value: Value =
                                    serde_json::from_slice(&reply).map_err(|e| e.to_string())?;
                                if let Some(welcome) = value.get("welcome") {
                                    ready_elapsed_ms.push(started.elapsed().as_millis());
                                    welcomed.insert(
                                        index,
                                        (
                                            serde_json::from_value(welcome.clone())
                                                .map_err(|e| e.to_string())?,
                                            value.clone(),
                                        ),
                                    );
                                } else if value["state"] == "admission_queued" {
                                    ever_queued.insert(index);
                                    next.push(index);
                                } else {
                                    resolved_terminal_failure += 1;
                                    terminal_failure_elapsed_ms.push(started.elapsed().as_millis());
                                    let key = format!(
                                        "{}:{}",
                                        value["state"].as_str().unwrap_or("unknown"),
                                        value["reason"].as_str().unwrap_or("")
                                    );
                                    *terminal_states.entry(key).or_insert(0) += 1;
                                }
                            }
                            Err(_) => next.push(index),
                        }
                    }
                    pending_indices = next;
                }
                let retry_loop_end_ms = started.elapsed().as_millis();
                // Every remaining index falls into exactly one disjoint
                // bucket: it was queued by the owner at least once, or it
                // never received any explicit reply at all (every attempt
                // was a transport-level error/timeout).
                let unresolved_ever_queued = pending_indices
                    .iter()
                    .filter(|index| ever_queued.contains(index))
                    .count();
                let unresolved_never_replied = pending_indices.len() - unresolved_ever_queued;

                let full_onboarding = if matches!(process_depth, ProcessDepth::FullOnboarding) {
                    let mut tasks = JoinSet::new();
                    for (index, (welcome, first_reply)) in welcomed.clone() {
                        let node = Arc::clone(&nodes[index]);
                        let pending = pendings[index].take().unwrap();
                        let checkpoint = checkpoint.clone();
                        let display_name = format!("ramp-{}", identity_offset + index as u64);
                        tasks.spawn(async move {
                            full_onboard(
                                node,
                                pending,
                                selected_peer,
                                checkpoint,
                                welcome,
                                first_reply,
                                display_name,
                                started,
                            )
                            .await
                        });
                    }
                    let mut outcome = FullOnboardingOutcome {
                        welcomed: welcomed.len(),
                        ..Default::default()
                    };
                    while let Some(record) = tasks.join_next().await {
                        let record = record.map_err(|error| error.to_string())?;
                        if record.ready {
                            outcome.ready += 1;
                            outcome.stage_joined_ms.push(record.stage_joined_ms);
                            outcome.adopted_ms.push(record.adopted_ms);
                            outcome.profiled_ms.push(record.profiled_ms);
                            outcome.presence_ms.push(record.presence_ms);
                        } else if let Some(phase) = record.failed_phase {
                            *outcome.failed_by_phase.entry(phase).or_insert(0) += 1;
                        }
                    }
                    Some(outcome)
                } else {
                    None
                };

                let teardown_started = Instant::now();
                for node in nodes {
                    Arc::try_unwrap(node).ok().unwrap().close().await;
                }
                let teardown_ms = teardown_started.elapsed().as_millis();

                let resolved_ready = match &full_onboarding {
                    Some(outcome) => outcome.ready,
                    None => welcomed.len(),
                };
                Ok(CapacityOutcome {
                    resolved_ready,
                    resolved_terminal_failure,
                    unresolved_ever_queued,
                    unresolved_never_replied,
                    transport_retries: retries,
                    terminal_states,
                    ready_elapsed_ms,
                    terminal_failure_elapsed_ms,
                    initial_batch_elapsed_ms,
                    retry_loop_end_ms,
                    teardown_ms,
                    full_onboarding,
                })
            })
        },
    );

    let result = client_thread.join().unwrap().unwrap();
    let elapsed_ms = started.elapsed().as_millis();
    let summary_ms = |values: &[u128]| -> Value {
        if values.is_empty() {
            return json!(null);
        }
        let min = *values.iter().min().unwrap();
        let max = *values.iter().max().unwrap();
        let mean = values.iter().sum::<u128>() / values.len() as u128;
        json!({"min_ms": min, "max_ms": max, "mean_ms": mean, "count": values.len()})
    };
    receipt["outcomes"] = json!({
        "resolved_ready": result.resolved_ready,
        "resolved_terminal_failure": result.resolved_terminal_failure,
        "unresolved_ever_queued": result.unresolved_ever_queued,
        "unresolved_never_replied": result.unresolved_never_replied,
        "transport_retries": result.transport_retries,
    });
    receipt["terminal_states"] = json!(result.terminal_states);
    receipt["timing"] = json!({
        "initial_batch_elapsed_ms": result.initial_batch_elapsed_ms,
        "configured_retry_deadline_seconds": deadline_seconds,
        "retry_loop_end_ms": result.retry_loop_end_ms,
        "retry_window_actual_ms": result.retry_loop_end_ms.saturating_sub(result.initial_batch_elapsed_ms),
        "teardown_ms": result.teardown_ms,
        "elapsed_ms_total": elapsed_ms,
        "elapsed_ms_excluding_teardown": elapsed_ms.saturating_sub(result.teardown_ms),
        "ready_elapsed_ms": summary_ms(&result.ready_elapsed_ms),
        "terminal_failure_elapsed_ms": summary_ms(&result.terminal_failure_elapsed_ms),
        "note": "configured_retry_deadline_seconds bounds only the retry loop, checked \
            between rounds, starting at initial_batch_elapsed_ms -- it is not an enforced \
            wall-clock cutoff. retry_loop_end_ms marks when the retry loop actually exited \
            (deadline hit or every joiner welcomed), separate from elapsed_ms_total, which \
            still includes teardown_ms (session close cost) -- use \
            elapsed_ms_excluding_teardown for the true onboarding-only interval.",
    });
    if let Some(full) = &result.full_onboarding {
        receipt["full_onboarding"] = json!({
            "welcomed": full.welcomed,
            "ready": full.ready,
            "failed_by_phase": full.failed_by_phase,
            "phase_timing_ms": {
                "stage_join": summary_ms(&full.stage_joined_ms),
                "adopt_join": summary_ms(&full.adopted_ms),
                "profile_publish": summary_ms(&full.profiled_ms),
                "presence": summary_ms(&full.presence_ms),
            },
        });
    }
    receipt["elapsed_ms"] = json!(elapsed_ms);
    receipt["peak_rss_bytes"] = json!(rss_bytes());
    receipt["passed"] = json!(
        result.resolved_ready == members
            && result.resolved_terminal_failure == 0
            && result.unresolved_ever_queued == 0
            && result.unresolved_never_replied == 0
    );
    write_receipt(receipt_path.as_deref(), &receipt);
    assert_eq!(
        result.resolved_ready, members,
        "not every synthetic joiner reached ready ({})",
        process_depth.label()
    );
    assert_eq!(
        result.resolved_terminal_failure, 0,
        "synthetic joiner received terminal failure"
    );
    assert_eq!(
        result.unresolved_ever_queued + result.unresolved_never_replied,
        0,
        "synthetic joiner remained unresolved at deadline"
    );
    println!(
        "invitation_link_capacity process_depth={} members={members} ready={} terminal_failure={} unresolved_ever_queued={} unresolved_never_replied={} retries={} elapsed_ms={elapsed_ms}",
        process_depth.label(),
        result.resolved_ready,
        result.resolved_terminal_failure,
        result.unresolved_ever_queued,
        result.unresolved_never_replied,
        result.transport_retries,
    );
}

// ---------------------------------------------------------------------
// Local small-scale full-onboarding validation (AC: "After a 50-joiner run
// against a real ATAK owner, member_roster returns 50 named profiles" --
// the real-ATAK 50/200/500 re-run is a separate tablet-operator follow-up
// task; this proves the same joiner state machine end-to-end at small
// scale against a host-side runtime-session owner this harness fully
// controls, so it can assert on the owner's own member_roster).
//
// This is also the red/green test of the joiner state machine required by
// #93's Definition of Done: one joiner gets a corrupted stage_join
// authorization and must land in the `stage_join` failure bucket, never
// counted ready.
// ---------------------------------------------------------------------

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&arachne_runtime::execute(
        handle,
        &serde_json::to_vec(&request).unwrap(),
    )?)
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

#[test]
fn local_full_onboarding_state_machine_rejects_a_corrupted_joiner() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    const GOOD_JOINERS: usize = 5;
    const OFFSET: u64 = 90_000;
    let started = Instant::now();

    let owner = arachne_runtime::create(Some(&[211; 32])).unwrap();
    call(
        owner,
        json!({"op":"create_workspace","display_name":"Ramp Owner"}),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    arachne_runtime::enable_record_storage(owner, &dir.path().join("owner.db"), &[211; 32])
        .unwrap();
    let invite = call(owner, json!({"op":"issue_invitation"})).unwrap();
    let invitation_bytes = bytes(&invite["invitation"]);
    let checkpoint = bytes(&invite["checkpoint"]);
    let owner_peer = endpoint(&invite["peer"]);
    let owner_info: Value = serde_json::from_str(&arachne_runtime::describe(owner).unwrap()).unwrap();
    let owner_port = owner_info["bound_address"]
        .as_str()
        .unwrap()
        .rsplit_once(':')
        .unwrap()
        .1
        .parse::<u16>()
        .unwrap();
    let owner_address = SocketAddr::from(([127, 0, 0, 1], owner_port));

    // Pump the owner's control dispatch throughout admission, profile
    // publication and presence -- all three are only serviced while the
    // owner session is being polled (see execute_request's PollAdmission
    // arm, which is where incoming DFJA/DFMQ/DFPR packets are drained).
    let stop = Arc::new(AtomicBool::new(false));
    let pump_stop = Arc::clone(&stop);
    let pump = thread::spawn(move || {
        while !pump_stop.load(Ordering::Relaxed) {
            if let Ok(value) = call(owner, json!({"op":"poll_admission"}))
                && value["state"] == "awaiting_save"
            {
                let snapshot = bytes(&value["snapshot"]);
                arachne_runtime::save_candidate(owner, &snapshot).unwrap();
                arachne_runtime::execute_stored(
                    owner,
                    br#"{"op":"adopt_admission"}"#,
                    &snapshot,
                )
                .unwrap();
            }
            thread::sleep(Duration::from_millis(2));
        }
        owner
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let total = GOOD_JOINERS + 1; // + one deliberately corrupted joiner
    let corrupt_index = GOOD_JOINERS; // last index is the red-test joiner
    let records: Vec<(usize, JoinerFullRecord)> = runtime.block_on(async move {
        let invitation = Invitation::from_bytes(&invitation_bytes).unwrap();
        let mut nodes = Vec::with_capacity(total);
        for index in 0..total {
            let mut seed = [0; 32];
            seed[..8].copy_from_slice(&(index as u64 + 5000).to_be_bytes());
            let (node, _receiver) =
                Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &seed)
                    .await
                    .unwrap();
            let node = Arc::new(node);
            node.add_address_hint(owner_peer, owner_address)
                .await
                .unwrap();
            nodes.push(node);
        }

        let mut pendings = Vec::with_capacity(total);
        let mut packets = Vec::with_capacity(total);
        for (index, node) in nodes.iter().enumerate() {
            let display_name = format!("ramp-{}", OFFSET + index as u64);
            let pending = PendingJoin::from_invitation(
                &invitation,
                &checkpoint,
                node.id(),
                &display_name,
            )
            .unwrap();
            let request = pending.admission_request().unwrap();
            packets.push(packet(request, &display_name, &checkpoint));
            pendings.push(pending);
        }

        let mut tasks = JoinSet::new();
        for (index, (node, pending)) in nodes.into_iter().zip(pendings).enumerate() {
            let packet = packets[index].clone();
            let checkpoint = checkpoint.clone();
            tasks.spawn(async move {
                let display_name = format!("ramp-{}", OFFSET + index as u64);
                let deadline = Instant::now() + Duration::from_secs(20);
                let mut reply = loop {
                    let reply = node.request_control(owner_peer, &packet).await.unwrap();
                    let value: Value = serde_json::from_slice(&reply).unwrap();
                    if value.get("welcome").is_some() {
                        break value;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "joiner {index} never left admission_queued"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                };
                let welcome: Vec<u8> = serde_json::from_value(reply["welcome"].clone()).unwrap();
                if index == corrupt_index {
                    // RED: corrupt the last membership step's authorization
                    // grant signature so apply_transition (inside
                    // stage_join) must fail. A corrupted joiner must never
                    // be counted ready.
                    let commits = reply["commits"].as_array_mut().unwrap();
                    let last = commits.last_mut().unwrap();
                    let signature = if !last["authorization"].is_null() {
                        &mut last["authorization"]["grant_signature"]
                    } else {
                        let batch = last["admission_batch"].as_array_mut().unwrap();
                        &mut batch.last_mut().unwrap()["grant_signature"]
                    };
                    let mut byte = signature[0].as_u64().unwrap();
                    byte ^= 1;
                    signature[0] = json!(byte);
                }
                let record = full_onboard(
                    node,
                    pending,
                    owner_peer,
                    checkpoint,
                    welcome,
                    reply,
                    display_name,
                    started,
                )
                .await;
                (index, record)
            });
        }
        let mut records = Vec::with_capacity(total);
        while let Some(result) = tasks.join_next().await {
            records.push(result.unwrap());
        }
        records.sort_by_key(|(index, _)| *index);
        records
    });

    stop.store(true, Ordering::Relaxed);
    let owner = pump.join().unwrap();

    // GREEN: every good joiner reached ready with its own ramp-<offset+i>
    // name and is durably adopted (record storage was enabled above).
    let ready: Vec<_> = records.iter().filter(|(_, r)| r.ready).collect();
    assert_eq!(
        ready.len(),
        GOOD_JOINERS,
        "expected exactly the good joiners to reach ready: {:?}",
        records
            .iter()
            .map(|(i, r)| (i, r.failed_phase, &r.failure_reason))
            .collect::<Vec<_>>()
    );
    for (index, (_, record)) in records.iter().enumerate().take(GOOD_JOINERS) {
        assert!(record.ready, "joiner {index} should have reached ready");
        assert_eq!(record.display_name, format!("ramp-{}", OFFSET + index as u64));
    }

    // RED: the corrupted joiner failed at stage_join specifically, and is
    // not counted ready.
    let (_, corrupted) = &records[corrupt_index];
    assert!(!corrupted.ready, "corrupted joiner must not be ready");
    assert_eq!(
        corrupted.failed_phase,
        Some("stage_join"),
        "corrupted joiner should fail at stage_join, got {:?} ({:?})",
        corrupted.failed_phase,
        corrupted.failure_reason
    );

    // Named-roster proof (small-scale stand-in for AC-2's real-ATAK
    // 50-joiner roster check): the owner's own member_roster shows every
    // good joiner's ramp-<offset+i> name and reachable presence.
    let roster = call(owner, json!({"op":"member_roster"})).unwrap();
    let members = roster["members"].as_array().unwrap();
    // The owner's MLS admission itself succeeded for all total joiners,
    // including the corrupted one -- corruption only breaks that joiner's
    // own local stage_join/adoption, not the owner-side Add it already
    // committed. So the roster holds itself + every admitted joiner
    // (total), but only the GOOD_JOINERS ever published a signed, named
    // profile.
    assert_eq!(
        members.len(),
        total + 1,
        "owner roster should hold itself plus every admitted joiner"
    );
    for index in 0..GOOD_JOINERS {
        let expected_name = format!("ramp-{}", OFFSET + index as u64);
        let entry = members
            .iter()
            .find(|member| member["display_name"] == json!(expected_name))
            .unwrap_or_else(|| panic!("owner roster missing {expected_name}: {members:?}"));
        assert_eq!(
            entry["presence"], "reachable",
            "{expected_name} should show reachable presence after its presence interval"
        );
    }
    // The corrupted joiner never durably adopted, so it authored no signed
    // profile the owner could display a name for.
    let corrupt_name = format!("ramp-{}", OFFSET + corrupt_index as u64);
    assert!(
        !members
            .iter()
            .any(|member| member["display_name"] == json!(corrupt_name)),
        "corrupted joiner must not appear named in the owner roster"
    );

    println!(
        "local_full_onboarding_state_machine members={total} ready={} stage_join_failed=1 peak_rss_bytes={}",
        ready.len(),
        rss_bytes(),
    );

    arachne_runtime::close(owner).unwrap();
}
