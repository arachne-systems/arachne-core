//! Rust-only qualification harness for real Iroh workspace onboarding.
//!
//! This is deliberately an executable instead of a Kotlin test. Every joiner
//! owns a real Iroh endpoint and performs the authenticated control exchange,
//! membership-history verification, workspace construction, profile exchange,
//! and presence exchange. The receipt contains timings and counts only; it
//! never contains invitations, payloads, endpoint IDs, or addresses.
//!
//! Fast smoke run:
//! `cargo run -p arachne-runtime --example real-iroh-qualification -- --endpoints 3`
//!
//! Scale run (Linux qualification host):
//! `cargo run --release -p arachne-runtime --example real-iroh-qualification -- --endpoints 500 --receipt .cache/iroh-500.json`

use arachne_node::{
    ConnectionBudget, MessageReceiver, NetworkProfile, Node, Permissions, RelayOptions,
};
use arachne_runtime::harness::{self, Query, StateBasis};
use arachne_runtime::{
    create, create_relay, create_relay_with_options, create_wan, describe, enable_record_storage,
    execute, restore_record_storage, save_candidate, wait_for_work,
};
use arachne_security::{AdmissionAuthorization, Invitation, MembershipAuthorization, PendingJoin};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio::task::JoinSet;

const HISTORY_PAGE_PACKET: &[u8] = b"DFJP\x01";
const MAX_ENDPOINTS: usize = 1_000;

#[derive(Clone, Copy, Debug)]
enum Profile {
    Direct,
    Gossip,
    Wan,
    Relay,
}

#[derive(Clone, Copy, Debug)]
enum Scenario {
    Baseline,
    Duplicate,
    Cancel,
    Restart,
    OwnerLoss,
    Refusal,
    Partition,
    QueuePressure,
    RelayLoss,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "baseline" => Ok(Self::Baseline),
            "duplicate" => Ok(Self::Duplicate),
            "cancel" => Ok(Self::Cancel),
            "restart" => Ok(Self::Restart),
            "owner-loss" => Ok(Self::OwnerLoss),
            "refusal" => Ok(Self::Refusal),
            "partition" => Ok(Self::Partition),
            "queue-pressure" => Ok(Self::QueuePressure),
            "relay-loss" => Ok(Self::RelayLoss),
            _ => Err(format!(
                "unknown scenario {value:?}; use baseline, duplicate, cancel, restart, owner-loss, refusal, partition, queue-pressure, or relay-loss"
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Duplicate => "duplicate",
            Self::Cancel => "cancel",
            Self::Restart => "restart",
            Self::OwnerLoss => "owner-loss",
            Self::Refusal => "refusal",
            Self::Partition => "partition",
            Self::QueuePressure => "queue-pressure",
            Self::RelayLoss => "relay-loss",
        }
    }
}

impl Profile {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "direct" => Ok(Self::Direct),
            "gossip" => Ok(Self::Gossip),
            "wan" => Ok(Self::Wan),
            "relay" => Ok(Self::Relay),
            _ => Err(format!(
                "unknown profile {value:?}; use direct, gossip, wan, or relay"
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Gossip => "gossip",
            Self::Wan => "wan",
            Self::Relay => "relay",
        }
    }

    fn node(self) -> NetworkProfile {
        match self {
            Self::Direct => NetworkProfile::Direct,
            Self::Gossip => NetworkProfile::Direct,
            Self::Wan => NetworkProfile::Wan,
            Self::Relay => NetworkProfile::RelayOnly,
        }
    }
}

#[derive(Clone, Debug)]
struct Options {
    endpoints: usize,
    profile: Profile,
    scenario: Scenario,
    relay_infrastructure: RelayInfrastructure,
    custom_relay: Option<RelayOptions>,
    relay_loss_after: Duration,
    deadline: Duration,
    receipt: Option<PathBuf>,
    seed: u64,
}

#[derive(Clone, Copy, Debug)]
enum RelayInfrastructure {
    Default,
    Staging,
    Local,
}

impl RelayInfrastructure {
    fn from_env() -> Self {
        if matches!(
            std::env::var("IROH_FORCE_STAGING_RELAYS"),
            Ok(value) if !value.is_empty()
        ) {
            Self::Staging
        } else {
            Self::Default
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "default" => Ok(Self::Default),
            "staging" => Ok(Self::Staging),
            "local" => Ok(Self::Local),
            _ => Err(format!(
                "unknown relay infrastructure {value:?}; use default, staging, or local"
            )),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Default => "iroh_default_relays",
            Self::Staging => "iroh_staging_relays",
            Self::Local => "arachne_local_relay",
        }
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{name} requires a value"))
}

impl Options {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut endpoints = 3;
        let mut profile = Profile::Direct;
        let mut scenario = Scenario::Baseline;
        let mut relay_infrastructure = RelayInfrastructure::from_env();
        let mut relay_loss_after = Duration::from_secs(3);
        let mut deadline = Duration::from_secs(300);
        let mut receipt = None;
        let mut seed = 0xA2C1_0000;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--endpoints" => {
                    endpoints = next_value(&mut args, "--endpoints")?
                        .parse()
                        .map_err(|_| "--endpoints must be an integer".to_string())?
                }
                "--profile" => profile = Profile::parse(&next_value(&mut args, "--profile")?)?,
                "--scenario" => scenario = Scenario::parse(&next_value(&mut args, "--scenario")?)?,
                "--relay-infrastructure" => {
                    relay_infrastructure = RelayInfrastructure::parse(&next_value(
                        &mut args,
                        "--relay-infrastructure",
                    )?)?
                }
                "--relay-loss-after-ms" => {
                    relay_loss_after = Duration::from_millis(
                        next_value(&mut args, "--relay-loss-after-ms")?
                            .parse()
                            .map_err(|_| "--relay-loss-after-ms must be an integer".to_string())?,
                    )
                }
                "--deadline-seconds" => {
                    deadline = Duration::from_secs(
                        next_value(&mut args, "--deadline-seconds")?
                            .parse()
                            .map_err(|_| "--deadline-seconds must be an integer".to_string())?,
                    )
                }
                "--receipt" => receipt = Some(PathBuf::from(next_value(&mut args, "--receipt")?)),
                "--seed" => {
                    seed = next_value(&mut args, "--seed")?
                        .parse()
                        .map_err(|_| "--seed must be an integer".to_string())?
                }
                "-h" | "--help" => return Err(Self::usage()),
                other => return Err(format!("unknown argument {other:?}\n{}", Self::usage())),
            }
        }
        if !(1..=MAX_ENDPOINTS).contains(&endpoints) {
            return Err(format!("--endpoints must be between 1 and {MAX_ENDPOINTS}"));
        }
        if matches!(
            scenario,
            Scenario::Cancel
                | Scenario::Restart
                | Scenario::OwnerLoss
                | Scenario::Refusal
                | Scenario::Partition
                | Scenario::RelayLoss
        ) && endpoints != 1
        {
            return Err(
                "--scenario cancel/restart/owner-loss/refusal/partition/relay-loss currently requires --endpoints 1"
                    .into(),
            );
        }
        if matches!(scenario, Scenario::QueuePressure) && endpoints < 2 {
            return Err("--scenario queue-pressure requires at least 2 endpoints".into());
        }
        if matches!(profile, Profile::Gossip) && !matches!(scenario, Scenario::Baseline) {
            return Err("--profile gossip currently requires --scenario baseline".into());
        }
        if matches!(profile, Profile::Gossip) && endpoints < 2 {
            return Err("--profile gossip requires at least 2 endpoints".into());
        }
        if matches!(scenario, Scenario::RelayLoss)
            && (!matches!(profile, Profile::Relay)
                || !matches!(relay_infrastructure, RelayInfrastructure::Local))
        {
            return Err(
                "--scenario relay-loss requires --profile relay and --relay-infrastructure local"
                    .into(),
            );
        }
        if deadline.is_zero() {
            return Err("--deadline-seconds must be positive".into());
        }
        Ok(Self {
            endpoints,
            profile,
            scenario,
            relay_infrastructure,
            custom_relay: None,
            relay_loss_after,
            deadline,
            receipt,
            seed,
        })
    }

    fn usage() -> String {
        "usage: real-iroh-qualification [--endpoints N] [--profile direct|gossip|wan|relay] [--relay-infrastructure default|staging|local] [--scenario baseline|duplicate|cancel|restart|owner-loss|refusal|partition|queue-pressure|relay-loss] [--relay-loss-after-ms N] [--deadline-seconds N] [--receipt PATH] [--seed N]".into()
    }
}

struct LocalRelay {
    options: RelayOptions,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl LocalRelay {
    fn start(loss_after: Option<Duration>) -> Result<Self, String> {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let thread = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
            };
            match runtime.block_on(iroh::test_utils::run_relay_server()) {
                Ok((map, _, server)) => {
                    let options =
                        RelayOptions::new(map, iroh::tls::CaTlsConfig::insecure_skip_verify());
                    let _ = ready_tx.send(Ok(options.clone()));
                    let mut stop_rx = stop_rx;
                    runtime.block_on(async move {
                        let mut server = Some(server);
                        match loss_after {
                            Some(delay) => {
                                tokio::select! {
                                    _ = &mut stop_rx => {}
                                    _ = tokio::time::sleep(delay) => {
                                        if let Some(server) = server.take() {
                                            let _ = server.shutdown().await;
                                        }
                                        let _ = stop_rx.await;
                                    }
                                }
                            }
                            None => {
                                let _ = stop_rx.await;
                            }
                        }
                        drop(server);
                    });
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                }
            }
        });
        let options = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|error| format!("local relay did not start: {error}"))??;
        Ok(Self {
            options,
            stop: Some(stop_tx),
            thread: Some(thread),
        })
    }
}

impl Drop for LocalRelay {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Owner {
    handle: i64,
    workspace: [u8; 32],
    peer: [u8; 32],
    address: SocketAddr,
    invitation: Vec<u8>,
    checkpoint: Vec<u8>,
    _records: TempDir,
}

#[derive(Default)]
struct Outcome {
    welcome_ms: Vec<u128>,
    stage_ms: Vec<u128>,
    profile_ms: Vec<u128>,
    presence_ms: Vec<u128>,
    cancelled: usize,
    owner_losses: usize,
    refusals: usize,
    partitions_recovered: usize,
    queue_peak: usize,
    relay_losses: usize,
    gossip_nodes: usize,
    gossip_neighbors: usize,
    gossip_sent: usize,
    gossip_received: usize,
    failures: BTreeMap<String, usize>,
}

impl Outcome {
    fn fail(&mut self, error: &str) {
        *self
            .failures
            .entry(failure_class(error).to_string())
            .or_default() += 1;
    }

    fn receipt(
        &self,
        options: &Options,
        elapsed: Duration,
        peak_nodes: usize,
        owner_metrics: Value,
    ) -> Value {
        let percentile = |values: &[u128], fraction: usize| -> Option<u128> {
            if values.is_empty() {
                return None;
            }
            let mut values = values.to_vec();
            values.sort_unstable();
            Some(values[(values.len() * fraction / 100).min(values.len() - 1)])
        };
        let phases_complete = [
            self.welcome_ms.len(),
            self.stage_ms.len(),
            self.profile_ms.len(),
            self.presence_ms.len(),
        ]
        .into_iter()
        .all(|completed| completed == options.endpoints);
        let complete = match options.scenario {
            Scenario::Cancel => self.cancelled == options.endpoints,
            Scenario::OwnerLoss => self.owner_losses == options.endpoints,
            Scenario::Refusal => self.refusals == options.endpoints,
            Scenario::Partition => self.partitions_recovered == options.endpoints,
            Scenario::QueuePressure => phases_complete && self.queue_peak > 0,
            Scenario::RelayLoss => self.relay_losses == options.endpoints,
            Scenario::Baseline | Scenario::Duplicate | Scenario::Restart => phases_complete,
        };
        let capacity_saturated = owner_metrics["paths"]["limited"].as_bool().unwrap_or(false)
            || owner_metrics["connection_capacity"]["refused"]
                .as_u64()
                .unwrap_or_default()
                > 0;
        let classification = if self.failures.is_empty() && complete {
            "passed"
        } else if capacity_saturated {
            "capacity_saturated"
        } else if self.failures.keys().any(|class| {
            matches!(
                class.as_str(),
                "connect_failure" | "connection_loss" | "deadline"
            )
        }) {
            "transport_or_environment_failure"
        } else {
            "incomplete_or_protocol_failure"
        };
        json!({
            "harness": "real_iroh_workspace_qualification",
            "passed": self.failures.is_empty() && complete,
            "classification": classification,
            "profile": options.profile.label(),
            "relay_infrastructure": relay_infrastructure(options.profile, options.relay_infrastructure),
            "scenario": options.scenario.label(),
            "real_iroh_endpoints": options.endpoints + 1,
            "joiners": options.endpoints,
            "seed": options.seed,
            "deadline_ms": options.deadline.as_millis(),
            "elapsed_ms": elapsed.as_millis(),
            "peak_joiner_endpoints": peak_nodes,
            "owner_metrics": owner_metrics,
            "phases": {
                "welcome": {"completed": self.welcome_ms.len(), "p50_ms": percentile(&self.welcome_ms, 50), "p95_ms": percentile(&self.welcome_ms, 95), "max_ms": self.welcome_ms.iter().max()},
                "stage_join": {"completed": self.stage_ms.len(), "p50_ms": percentile(&self.stage_ms, 50), "p95_ms": percentile(&self.stage_ms, 95), "max_ms": self.stage_ms.iter().max()},
                "profile": {"completed": self.profile_ms.len(), "p50_ms": percentile(&self.profile_ms, 50), "p95_ms": percentile(&self.profile_ms, 95), "max_ms": self.profile_ms.iter().max()},
                "presence": {"completed": self.presence_ms.len(), "p50_ms": percentile(&self.presence_ms, 50), "p95_ms": percentile(&self.presence_ms, 95), "max_ms": self.presence_ms.iter().max()},
            },
            "cancellation": {"completed": self.cancelled},
            "owner_loss": {"observed": self.owner_losses},
            "refusal": {"observed": self.refusals},
            "partition": {"recovered": self.partitions_recovered},
            "queue_pressure": {"peak": self.queue_peak},
            "relay_loss": {"observed": self.relay_losses, "reconnected": 0, "outcome": "explicit_failure"},
            "gossip": {"nodes_with_neighbors": self.gossip_nodes, "neighbors": self.gossip_neighbors, "messages_sent": self.gossip_sent, "messages_received": self.gossip_received},
            "failures": self.failures,
            "evidence_ceiling": "real Rust/Iroh endpoints on this host; not tablet, WAN, relay, or impaired-network evidence unless the selected profile and external network setup provide it",
        })
    }
}

fn failure_class(error: &str) -> &'static str {
    let error = error.to_ascii_lowercase();
    if error.contains("deadline") || error.contains("timed out") {
        "deadline"
    } else if error.contains("connection lost") || error.contains("connection closed") {
        "connection_loss"
    } else if error.contains("connect") {
        "connect_failure"
    } else if error.contains("denied") || error.contains("permission") {
        "authorization"
    } else if error.contains("decode") || error.contains("reply") || error.contains("state") {
        "protocol"
    } else if error.contains("bind") {
        "bind_failure"
    } else {
        "operation_failure"
    }
}

fn relay_infrastructure(profile: Profile, infrastructure: RelayInfrastructure) -> &'static str {
    if !matches!(profile, Profile::Relay) {
        return "not_applicable";
    }
    infrastructure.label()
}

/// Keep benchmark receipts useful for operators without copying workspace IDs,
/// endpoint IDs, routes, addresses, invitations, or payloads into artifacts.
fn compact_metrics(value: &Value) -> Value {
    let paths = value["paths"].as_array().map_or(&[][..], Vec::as_slice);
    let mut routes = BTreeMap::<&'static str, usize>::new();
    for path in paths {
        if let Some(route) = path["route"].as_str().map(|route| match route {
            "direct" => "direct",
            "relay" => "relay",
            "tor" => "tor",
            _ => "custom",
        }) {
            *routes.entry(route).or_default() += 1;
        }
    }
    json!({
        "received_bytes": value["received_bytes"],
        "sent_bytes": value["sent_bytes"],
        "receive_queue": value["receive_queue"],
        "admission_queue": value["admission_queue"],
        "admission_queue_bytes": value["admission_queue_bytes"],
        "admission_waiters": value["admission_waiters"],
        "admission_in_flight": value["admission_in_flight"],
        "approval_pending": value["approval_pending"],
        "pending_objects": value["pending_objects"],
        "repair_jobs": value["repair_jobs"],
        "gossip_neighbors": value["gossip_neighbors"],
        "membership_gossip": value["membership_gossip"],
        "control_timing": value["control_timing"],
        "connection_capacity": value["connection_capacity"],
        "paths": {"total": paths.len(), "by_route": routes, "limited": value["paths_limited"]},
    })
}

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(
        handle,
        &serde_json::to_vec(&request).map_err(|e| e.to_string())?,
    )?)
    .map_err(|e| e.to_string())
}

fn bytes(value: &Value) -> Result<Vec<u8>, String> {
    value
        .as_array()
        .ok_or("expected byte array".to_string())?
        .iter()
        .map(|byte| {
            byte.as_u64()
                .ok_or("invalid byte".to_string())
                .and_then(|byte| u8::try_from(byte).map_err(|_| "invalid byte".to_string()))
        })
        .collect()
}

fn array32(value: &Value) -> Result<[u8; 32], String> {
    bytes(value)?
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())
}

fn array64(value: &Value) -> Result<[u8; 64], String> {
    bytes(value)?
        .try_into()
        .map_err(|_| "expected 64 bytes".to_string())
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

fn history_packet(request: &[u8], checkpoint: &[u8], offset: u32) -> Vec<u8> {
    let mut packet = HISTORY_PAGE_PACKET.to_vec();
    packet.extend((request.len() as u32).to_be_bytes());
    packet.extend((checkpoint.len() as u32).to_be_bytes());
    packet.extend(offset.to_be_bytes());
    packet.extend(request);
    packet.extend(checkpoint);
    packet
}

fn authorization(value: &Value) -> Result<AdmissionAuthorization, String> {
    Ok(AdmissionAuthorization {
        invitation_key: array32(&value["invitation_key"])?,
        grant_signature: array64(&value["grant_signature"])?,
        redemption_signature: array64(&value["redemption_signature"])?,
    })
}

fn steps(value: &Value) -> Result<Vec<(MembershipAuthorization, Vec<u8>)>, String> {
    value["commits"]
        .as_array()
        .ok_or("admission reply has no commits".to_string())?
        .iter()
        .map(|step| {
            let commit = bytes(&step["commit"])?;
            let auth = if !step["authorization"].is_null() {
                MembershipAuthorization::Admission(authorization(&step["authorization"])?)
            } else {
                MembershipAuthorization::AdmissionBatch(
                    step["admission_batch"]
                        .as_array()
                        .ok_or("unsupported admission step".to_string())?
                        .iter()
                        .map(authorization)
                        .collect::<Result<_, _>>()?,
                )
            };
            Ok((auth, commit))
        })
        .collect()
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    (!remaining.is_zero())
        .then_some(remaining)
        .ok_or_else(|| "deadline exceeded".to_string())
}

async fn close_handle(handle: i64) -> Result<(), String> {
    tokio::task::spawn_blocking(move || arachne_runtime::close(handle))
        .await
        .map_err(|error| error.to_string())?
}

async fn request_control(
    node: &Node,
    peer: [u8; 32],
    payload: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let remaining = remaining(deadline)?;
    tokio::time::timeout(remaining, node.request_control(peer, payload))
        .await
        .map_err(|_| "deadline exceeded".to_string())?
        .map_err(|error| error.to_string())
}

async fn request_until_welcome(
    node: &Node,
    peer: [u8; 32],
    payload: &[u8],
    deadline: Instant,
) -> Result<Value, String> {
    loop {
        let reply = request_control(node, peer, payload, deadline).await?;
        let value: Value = serde_json::from_slice(&reply).map_err(|e| {
            format!(
                "control reply JSON decode failed ({} bytes): {e}",
                reply.len()
            )
        })?;
        match value["state"].as_str() {
            Some("admission_queued") | Some("admission_waiting") => tokio::task::yield_now().await,
            Some("admission_replied") | None if value.get("welcome").is_some() => return Ok(value),
            Some(state) => return Err(format!("admission ended in {state}")),
            None => return Err("admission reply has no state".into()),
        }
    }
}

async fn full_join(
    node: Arc<Node>,
    owner: &OwnerData,
    invitation: Invitation,
    checkpoint: Vec<u8>,
    name: String,
    scenario: Scenario,
    started: Instant,
    deadline: Instant,
) -> Result<(u128, u128, u128, u128), String> {
    let pending = PendingJoin::from_invitation(&invitation, &checkpoint, node.id(), &name)
        .map_err(str::to_owned)?;
    full_join_with_pending(node, owner, pending, name, scenario, started, deadline).await
}

async fn full_join_with_pending(
    node: Arc<Node>,
    owner: &OwnerData,
    pending: PendingJoin,
    name: String,
    scenario: Scenario,
    started: Instant,
    deadline: Instant,
) -> Result<(u128, u128, u128, u128), String> {
    let request = pending.admission_request().map_err(str::to_owned)?.to_vec();
    let checkpoint = pending
        .admission_checkpoint()
        .map_err(str::to_owned)?
        .to_vec();
    let payload = packet(&request, &name, &checkpoint);
    let first = request_until_welcome(&node, owner.peer, &payload, deadline)
        .await
        .map_err(|error| format!("welcome: {error}"))?;
    let welcome_ms = started.elapsed().as_millis();
    if matches!(scenario, Scenario::Duplicate) {
        let duplicate = request_until_welcome(&node, owner.peer, &payload, deadline)
            .await
            .map_err(|error| format!("duplicate: {error}"))?;
        if duplicate.get("welcome").is_none() {
            return Err("duplicate: retained admission omitted Welcome".into());
        }
    }
    let welcome = bytes(&first["welcome"])?;
    let mut all_steps = steps(&first)?;
    let mut page = first;
    while !page["history_complete"].as_bool().unwrap_or(true) {
        let offset = page["history_next"]
            .as_u64()
            .ok_or("history page has no offset")? as u32;
        let reply = request_control(
            &node,
            owner.peer,
            &history_packet(&request, &checkpoint, offset),
            deadline,
        )
        .await
        .map_err(|error| format!("history: {error}"))?;
        page = serde_json::from_slice(&reply).map_err(|e| {
            format!(
                "history reply JSON decode failed ({} bytes): {e}",
                reply.len()
            )
        })?;
        all_steps.extend(steps(&page)?);
    }
    let mut proof = pending.join_proof().map_err(str::to_owned)?;
    for (authorization, commit) in all_steps {
        proof
            .apply_transition(&authorization, &commit)
            .map_err(str::to_owned)?;
    }
    let workspace = pending
        .prepare_workspace(&proof, &welcome)
        .map_err(str::to_owned)?;
    let member = workspace.member().ok_or("joined workspace has no member")?;
    if !workspace
        .member_roster()
        .map_err(str::to_owned)?
        .iter()
        .any(|row| row.id == member.id())
    {
        return Err("joined workspace roster omitted self".into());
    }
    let stage_ms = started.elapsed().as_millis();

    let profile = workspace.sign_member_profile().map_err(str::to_owned)?;
    let name_head = workspace.workspace_name_head().unwrap_or([0; 32]);
    let query = Query {
        workspace: workspace.id(),
        basis: StateBasis::new(workspace.epoch(), workspace.epoch_fingerprint(), name_head),
        profiles_digest: [0; 32],
        profiles: [profile.as_slice(), &[]],
    };
    let reply = request_control(
        &node,
        owner.peer,
        &harness::encode_query(&query).map_err(|e| e.to_string())?,
        deadline,
    )
    .await
    .map_err(|error| format!("profile: {error}"))?;
    let reply = harness::decode_reply(&reply).map_err(|e| e.to_string())?;
    if reply["state"] == "membership_denied" {
        return Err("owner denied member profile".into());
    }
    let profile_ms = started.elapsed().as_millis();

    let mut instance = [0; 16];
    instance[..8].copy_from_slice(&(node.id()[0] as u64).to_be_bytes());
    let presence = harness::harness_presence_packet(&workspace, instance, true);
    request_control(&node, owner.peer, &presence, deadline)
        .await
        .map_err(|error| format!("presence: {error}"))?;
    let presence_ms = started.elapsed().as_millis();
    Ok((welcome_ms, stage_ms, profile_ms, presence_ms))
}

#[derive(Clone, Copy)]
struct OwnerData {
    peer: [u8; 32],
    address: SocketAddr,
}

async fn close_nodes(nodes: &mut Vec<Arc<Node>>) {
    let mut closes = JoinSet::new();
    while let Some(node) = nodes.pop() {
        if let Ok(node) = Arc::try_unwrap(node) {
            closes.spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(1), node.close()).await;
            });
        }
    }
    while closes.join_next().await.is_some() {}
}

async fn enable_gossip_profile(
    nodes: &[Arc<Node>],
    owner_handle: i64,
    owner_peer: [u8; 32],
    workspace: [u8; 32],
    deadline: Instant,
    outcomes: &mut Outcome,
) {
    let mut policy = BTreeMap::new();
    policy.insert(owner_peer, Permissions::AllTopics);
    for node in nodes {
        policy.insert(node.id(), Permissions::AllTopics);
    }
    let owner_policy = tokio::task::spawn_blocking(move || {
        call(
            owner_handle,
            json!({"op":"install_member_policy","revision":1,"topics":["qualification/gossip"]}),
        )
    })
    .await
    .map_err(|error| error.to_string())
    .and_then(|result| result.map(|_| ()))
    .map_err(|error| format!("gossip owner policy: {error}"));
    if let Err(error) = owner_policy {
        outcomes.fail(&error);
        return;
    }

    let addresses: Vec<_> = nodes
        .iter()
        .map(|node| (node.id(), node.address()))
        .collect();
    for node in nodes {
        for (peer, address) in &addresses {
            if *peer == node.id() {
                continue;
            }
            let result = match remaining(deadline) {
                Ok(limit) => tokio::time::timeout(limit, node.add_address_hint(*peer, *address))
                    .await
                    .map_err(|_| "gossip address hint deadline".to_string())
                    .and_then(|result| result.map_err(|error| error.to_string())),
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                outcomes.fail(&format!("gossip hint: {error}"));
                return;
            }
        }
        let node_policy = policy.clone();
        let result = match remaining(deadline) {
            Ok(limit) => tokio::time::timeout(limit, async {
                node.install_verified_policy(workspace, 1, node_policy)
                    .await
                    .map_err(|error| error.to_string())?;
                node.enable_gossip(workspace, 1)
                    .await
                    .map_err(|error| error.to_string())
            })
            .await
            .map_err(|_| "gossip overlay setup deadline".to_string())
            .and_then(|result| result),
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            outcomes.fail(&format!("gossip setup: {error}"));
            return;
        }
    }

    let mut waits = JoinSet::new();
    for node in nodes {
        let node = Arc::clone(node);
        let limit = match remaining(deadline) {
            Ok(limit) => limit,
            Err(error) => {
                outcomes.fail(&format!("gossip neighbor: {error}"));
                return;
            }
        };
        waits.spawn(async move {
            tokio::time::timeout(limit, node.wait_for_gossip_neighbor(workspace))
                .await
                .map_err(|_| "gossip neighbor deadline".to_string())
                .and_then(|joined| {
                    joined
                        .then_some(())
                        .ok_or_else(|| "gossip overlay unavailable".to_string())
                })
        });
    }
    while let Some(result) = waits.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => outcomes.fail(&format!("gossip neighbor: {error}")),
            Err(error) => outcomes.fail(&format!("gossip neighbor task: {error}")),
        }
    }
    for node in nodes {
        let neighbors = node.live_neighbor_count(workspace).await;
        outcomes.gossip_neighbors = outcomes.gossip_neighbors.saturating_add(neighbors);
        if neighbors > 0 {
            outcomes.gossip_nodes = outcomes.gossip_nodes.saturating_add(1);
        }
    }

    let peer_ids: Vec<_> = nodes.iter().map(|node| node.id()).collect();
    let mut sender_index = None;
    let mut target_indices = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        let neighbors = node.live_neighbors(workspace).await;
        let targets: Vec<_> = neighbors
            .into_iter()
            .filter_map(|peer| peer_ids.iter().position(|candidate| *candidate == peer))
            .collect();
        if !targets.is_empty() {
            sender_index = Some(index);
            target_indices = targets;
            break;
        }
    }
    let Some(sender_index) = sender_index else {
        outcomes.fail("gossip overlay has no joiner-to-joiner neighbor");
        return;
    };
    let expected = b"qualification-gossip-roundtrip".to_vec();
    let sender = Arc::clone(&nodes[sender_index]);
    let sent = match remaining(deadline) {
        Ok(limit) => tokio::time::timeout(
            limit,
            sender.broadcast_membership(workspace, expected.clone()),
        )
        .await
        .map_err(|_| "gossip broadcast deadline".to_string())
        .and_then(|result| result.map_err(|error| error.to_string())),
        Err(error) => Err(error),
    };
    match sent {
        Ok(true) => outcomes.gossip_sent = 1,
        Ok(false) => {
            outcomes.fail("gossip broadcast had no overlay neighbor");
            return;
        }
        Err(error) => {
            outcomes.fail(&format!("gossip broadcast: {error}"));
            return;
        }
    }

    let mut deliveries = JoinSet::new();
    for index in target_indices {
        let node = Arc::clone(&nodes[index]);
        let limit = match remaining(deadline) {
            Ok(limit) => limit,
            Err(error) => {
                outcomes.fail(&format!("gossip delivery: {error}"));
                return;
            }
        };
        deliveries.spawn(async move {
            tokio::time::timeout(limit, node.wait_for_membership_gossip(workspace))
                .await
                .map_err(|_| "gossip delivery deadline".to_string())
                .map(|payload| payload.ok_or_else(|| "gossip delivery unavailable".to_string()))
                .and_then(|payload| payload)
        });
    }
    let mut received = false;
    while let Some(result) = deliveries.join_next().await {
        match result {
            Ok(Ok(payload)) if payload == expected => {
                outcomes.gossip_received = 1;
                received = true;
                deliveries.abort_all();
                break;
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => outcomes.fail(&format!("gossip delivery: {error}")),
            Err(error) => outcomes.fail(&format!("gossip delivery task: {error}")),
        }
    }
    while deliveries.join_next().await.is_some() {}
    if !received {
        outcomes.fail("gossip membership envelope was not received");
    }
}

async fn close_node_before(node: Arc<Node>, deadline: Instant) {
    if let Ok(node) = Arc::try_unwrap(node) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let _ = tokio::time::timeout(remaining, node.close()).await;
    }
}

fn create_endpoint_for_profile(
    profile: Profile,
    secret: &[u8; 32],
    relay: Option<&RelayOptions>,
) -> Result<i64, String> {
    match profile {
        Profile::Direct | Profile::Gossip => create(Some(secret)),
        Profile::Wan => create_wan(secret),
        Profile::Relay => relay.map_or_else(
            || create_relay(secret),
            |relay| create_relay_with_options(secret, relay.clone()),
        ),
    }
}

fn create_owner(
    seed: u64,
    profile: Profile,
    relay: Option<&RelayOptions>,
) -> Result<Owner, String> {
    let mut secret = [0; 32];
    secret[..8].copy_from_slice(&seed.to_be_bytes());
    let handle = create_endpoint_for_profile(profile, &secret, relay)?;
    let records = tempfile::tempdir().map_err(|e| e.to_string())?;
    let result = (|| {
        let created = call(
            handle,
            json!({"op":"create_workspace","display_name":"Qualification owner","workspace_name":"Rust qualification"}),
        )?;
        let workspace = array32(&created["workspace"])?;
        enable_record_storage(handle, &records.path().join("owner.db"), &secret)?;
        let staged = call(
            handle,
            json!({"op":"stage_invitation","personal":false,"expires_at":0}),
        )?;
        save_candidate(handle, &bytes(&staged["snapshot"])?)?;
        let invitation = call(
            handle,
            json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
        )?["issued_invitation"]
            .clone();
        let info: Value = serde_json::from_str(&describe(handle)?).map_err(|e| e.to_string())?;
        let peer = array32(&info["endpoint_key"])?;
        let port = info["bound_address"]
            .as_str()
            .ok_or("owner has no bound address")?
            .rsplit_once(':')
            .ok_or("owner address is malformed")?
            .1
            .parse::<u16>()
            .map_err(|_| "owner port is malformed")?;
        Ok(Owner {
            handle,
            workspace,
            peer,
            address: ([127, 0, 0, 1], port).into(),
            invitation: bytes(&invitation["invitation"])?,
            checkpoint: bytes(&invitation["checkpoint"])?,
            _records: records,
        })
    })();
    if result.is_err() {
        let _ = arachne_runtime::close(handle);
    }
    result
}

fn restore_owner(
    owner: Owner,
    seed: u64,
    profile: Profile,
    relay: Option<&RelayOptions>,
) -> Result<Owner, String> {
    let Owner {
        handle,
        workspace,
        invitation,
        checkpoint,
        _records: records,
        ..
    } = owner;
    let path = records.path().join("owner.db");
    // The partition phase closes the first endpoint before restoring its
    // records; a repeated close is expected here.
    let _ = arachne_runtime::close(handle);
    let mut secret = [0; 32];
    secret[..8].copy_from_slice(&seed.to_be_bytes());
    let handle = create_endpoint_for_profile(profile, &secret, relay)?;
    let result = (|| {
        restore_record_storage(handle, &path, &secret, workspace)?;
        let info: Value = serde_json::from_str(&describe(handle)?).map_err(|e| e.to_string())?;
        let peer = array32(&info["endpoint_key"])?;
        let port = info["bound_address"]
            .as_str()
            .ok_or("restored owner has no bound address")?
            .rsplit_once(':')
            .ok_or("restored owner address is malformed")?
            .1
            .parse::<u16>()
            .map_err(|_| "restored owner port is malformed")?;
        Ok(Owner {
            handle,
            workspace,
            peer,
            address: ([127, 0, 0, 1], port).into(),
            invitation,
            checkpoint,
            _records: records,
        })
    })();
    if result.is_err() {
        let _ = arachne_runtime::close(handle);
    }
    result
}

async fn bind_node(
    address: SocketAddr,
    secret: Option<&[u8; 32]>,
    profile: NetworkProfile,
    budget: ConnectionBudget,
    relay: Option<&RelayOptions>,
) -> std::result::Result<(Node, MessageReceiver), arachne_node::Error> {
    match relay {
        Some(relay) => {
            Node::bind_with_profile_and_relay(address, secret, profile, budget, relay.clone()).await
        }
        None => Node::bind_with_profile(address, secret, profile, budget).await,
    }
}

async fn run_nodes(
    options: Options,
    owner: OwnerData,
    owner_handle: i64,
    workspace: [u8; 32],
    invitation: Vec<u8>,
    checkpoint: Vec<u8>,
    done: Arc<AtomicUsize>,
    deadline: Instant,
) -> Result<(Outcome, usize, Value), String> {
    let started = Instant::now();
    let profile = options.profile.node();
    let mut binds = JoinSet::new();
    for index in 0..options.endpoints {
        let seed = options.seed.wrapping_add(index as u64 + 1);
        let relay = options.custom_relay.clone();
        binds.spawn(async move {
            let mut secret = [0; 32];
            secret[..8].copy_from_slice(&seed.to_be_bytes());
            let remaining = remaining(deadline)?;
            tokio::time::timeout(
                remaining,
                bind_node(
                    ([127, 0, 0, 1], 0).into(),
                    Some(&secret),
                    profile,
                    ConnectionBudget::default(),
                    relay.as_ref(),
                ),
            )
            .await
            .map_err(|_| "deadline exceeded while binding endpoint".to_string())?
            .map(|(node, _)| Arc::new(node))
            .map_err(|e| e.to_string())
        });
    }
    let mut nodes = Vec::with_capacity(options.endpoints);
    while let Some(result) = binds.join_next().await {
        match result.map_err(|e| e.to_string())? {
            Ok(node) => nodes.push(node),
            Err(error) => {
                close_nodes(&mut nodes).await;
                return Err(error);
            }
        }
    }
    let peak_nodes = nodes.len();
    if matches!(
        options.profile,
        Profile::Direct | Profile::Gossip | Profile::Wan
    ) {
        for node in &nodes {
            let result = tokio::time::timeout(
                remaining(deadline)?,
                node.add_address_hint(owner.peer, owner.address),
            )
            .await
            .map_err(|_| "deadline exceeded while adding address hint".to_string())?
            .map_err(|e| e.to_string());
            if let Err(error) = result {
                close_nodes(&mut nodes).await;
                return Err(error);
            }
        }
    }
    let mut requests = JoinSet::new();
    for (index, node) in nodes.iter().enumerate() {
        let node = Arc::clone(node);
        let owner = OwnerData {
            peer: owner.peer,
            address: owner.address,
        };
        let invitation = invitation.clone();
        let checkpoint = checkpoint.clone();
        let name = format!("qualification-{}", index + 1);
        let failure_name = name.clone();
        let diagnostics_node = Arc::clone(&node);
        requests.spawn(async move {
            let invitation = Invitation::from_bytes(&invitation).map_err(str::to_owned)?;
            full_join(
                node,
                &owner,
                invitation,
                checkpoint,
                name,
                options.scenario,
                started,
                deadline,
            )
            .await
            .map_err(|error| {
                let metrics = diagnostics_node.transport_metrics();
                format!(
                    "{failure_name}: {error} (paths={}, sent={}, received={})",
                    metrics.paths.len(),
                    metrics.sent_bytes,
                    metrics.received_bytes
                )
            })
        });
    }
    let mut outcomes = Outcome::default();
    while let Some(result) = requests.join_next().await {
        match result.map_err(|e| e.to_string())? {
            Ok((welcome, stage, profile, presence)) => {
                outcomes.welcome_ms.push(welcome);
                outcomes.stage_ms.push(stage);
                outcomes.profile_ms.push(profile);
                outcomes.presence_ms.push(presence);
            }
            Err(_error) if matches!(options.scenario, Scenario::RelayLoss) => {
                outcomes.relay_losses += 1;
            }
            Err(error) => outcomes.fail(&error),
        }
        done.fetch_add(1, Ordering::Release);
    }
    if matches!(options.profile, Profile::Gossip) {
        enable_gossip_profile(
            &nodes,
            owner_handle,
            owner.peer,
            workspace,
            deadline,
            &mut outcomes,
        )
        .await;
    }
    let owner_metrics =
        tokio::task::spawn_blocking(move || call(owner_handle, json!({"op": "workspace_metrics"})))
            .await
            .map_err(|error| error.to_string());
    close_nodes(&mut nodes).await;
    let owner_metrics = compact_metrics(&owner_metrics??);
    Ok((outcomes, peak_nodes, owner_metrics))
}

async fn cancel_join(
    node: Arc<Node>,
    owner: OwnerData,
    invitation: Vec<u8>,
    checkpoint: Vec<u8>,
    owner_handle: i64,
    deadline: Instant,
) -> Result<(), String> {
    let invitation = Invitation::from_bytes(&invitation).map_err(str::to_owned)?;
    let pending = PendingJoin::from_invitation(&invitation, &checkpoint, node.id(), "cancelled")
        .map_err(str::to_owned)?;
    let request = pending.admission_request().map_err(str::to_owned)?.to_vec();
    let payload = packet(&request, "cancelled", &checkpoint);
    tokio::time::timeout(
        remaining(deadline)?,
        node.add_address_hint(owner.peer, owner.address),
    )
    .await
    .map_err(|_| "deadline exceeded while adding address hint".to_string())?
    .map_err(|error| error.to_string())?;

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let waiter = thread::spawn(move || {
        let _ = ready_tx.send(wait_for_work(owner_handle));
    });
    let cancellation = node.control_cancellation();
    let requester = Arc::clone(&node);
    let request_task =
        tokio::spawn(async move { requester.request_control(owner.peer, &payload).await });
    let wait_for_signal = remaining(deadline)?;
    let ready =
        match tokio::task::spawn_blocking(move || ready_rx.recv_timeout(wait_for_signal)).await {
            Ok(Ok(Ok(ready))) => ready,
            Ok(Ok(Err(error))) => {
                cancellation.send_replace(true);
                request_task.abort();
                let _ = request_task.await;
                let _ = close_handle(owner_handle).await;
                let _ = waiter.join();
                return Err(format!(
                    "owner did not observe cancellation request: {error}"
                ));
            }
            Ok(Err(error)) => {
                cancellation.send_replace(true);
                request_task.abort();
                let _ = request_task.await;
                let _ = close_handle(owner_handle).await;
                let _ = waiter.join();
                return Err(format!("owner wait channel failed: {error}"));
            }
            Err(error) => {
                cancellation.send_replace(true);
                request_task.abort();
                let _ = request_task.await;
                let _ = close_handle(owner_handle).await;
                let _ = waiter.join();
                return Err(format!("owner wait task failed: {error}"));
            }
        };
    if !ready {
        cancellation.send_replace(true);
        request_task.abort();
        let _ = request_task.await;
        let _ = close_handle(owner_handle).await;
        let _ = waiter.join();
        return Err("owner work signal closed before cancellation request".into());
    }
    cancellation.send_replace(true);
    let request_result = request_task
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| match error {
            arachne_node::Error::Cancelled => "cancelled".to_string(),
            error => error.to_string(),
        });
    let waiter_result = waiter
        .join()
        .map_err(|_| "owner wait thread panicked".to_string());
    match (request_result, ready, waiter_result) {
        (Err(error), true, Ok(())) if error == "cancelled" => Ok(()),
        (Err(error), true, Ok(())) => Err(error),
        (Err(_), false, Ok(())) => Err("owner closed before cancellation completed".into()),
        (Err(error), true, Err(join_error)) => Err(format!("{error}; {join_error}")),
        (Ok(_), _, _) => Err("cancel request completed instead of being cancelled".into()),
        (Err(error), _, Err(join_error)) => Err(format!("{error}; {join_error}")),
    }
}

fn run_owner_loss(options: Options) -> Result<Value, String> {
    let started = Instant::now();
    let owner = create_owner(options.seed, options.profile, options.custom_relay.as_ref())?;
    let owner_handle = owner.handle;
    let owner_data = OwnerData {
        peer: owner.peer,
        address: owner.address,
    };
    let invitation = owner.invitation.clone();
    let checkpoint = owner.checkpoint.clone();
    let deadline = started + options.deadline;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let result = runtime.block_on(async {
        let mut secret = [0; 32];
        secret[..8].copy_from_slice(&options.seed.wrapping_add(1).to_be_bytes());
        let (node, _) = tokio::time::timeout(
            remaining(deadline)?,
            bind_node(
                ([127, 0, 0, 1], 0).into(),
                Some(&secret),
                options.profile.node(),
                ConnectionBudget::default(),
                options.custom_relay.as_ref(),
            ),
        )
        .await
        .map_err(|_| "deadline exceeded while binding endpoint".to_string())?
        .map_err(|error| error.to_string())?;
        let node = Arc::new(node);
        let invitation = Invitation::from_bytes(&invitation).map_err(str::to_owned)?;
        let pending = PendingJoin::from_invitation(&invitation, &checkpoint, node.id(), "loss")
            .map_err(str::to_owned)?;
        let request = pending.admission_request().map_err(str::to_owned)?.to_vec();
        let payload = packet(&request, "loss", &checkpoint);
        tokio::time::timeout(
            remaining(deadline)?,
            node.add_address_hint(owner_data.peer, owner_data.address),
        )
        .await
        .map_err(|_| "deadline exceeded while adding address hint".to_string())?
        .map_err(|error| error.to_string())?;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            let _ = ready_tx.send(wait_for_work(owner_handle));
        });
        let requester = Arc::clone(&node);
        let request_task =
            tokio::spawn(async move { requester.request_control(owner_data.peer, &payload).await });
        let ready = tokio::task::spawn_blocking(move || {
            ready_rx.recv_timeout(remaining(deadline).unwrap_or_default())
        })
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
        if !ready {
            request_task.abort();
            let _ = request_task.await;
            let _ = close_handle(owner_handle).await;
            let _ = waiter.join();
            return Err("owner-loss: owner work signal closed before request".into());
        }
        close_handle(owner_handle).await?;
        let request_result = request_task.await.map_err(|error| error.to_string())?;
        waiter
            .join()
            .map_err(|_| "owner-loss: owner wait thread panicked".to_string())?;
        if request_result.is_ok() {
            return Err("owner-loss: request completed after owner shutdown".into());
        }
        close_node_before(node, deadline).await;
        Ok::<_, String>((
            Outcome {
                owner_losses: 1,
                ..Outcome::default()
            },
            1,
            json!({"owner_closed": true}),
        ))
    });
    let _ = arachne_runtime::close(owner_handle);
    let (outcomes, peak_nodes, owner_metrics) = result?;
    let receipt = outcomes.receipt(&options, started.elapsed(), peak_nodes, owner_metrics);
    write_receipt(&options, &receipt)?;
    if !receipt["passed"].as_bool().unwrap_or(false) {
        return Err(receipt.to_string());
    }
    Ok(receipt)
}

fn run_refusal(options: Options) -> Result<Value, String> {
    let started = Instant::now();
    let owner = create_owner(options.seed, options.profile, options.custom_relay.as_ref())?;
    let owner_handle = owner.handle;
    let owner_data = OwnerData {
        peer: owner.peer,
        address: owner.address,
    };
    let invitation = owner.invitation.clone();
    let checkpoint = owner.checkpoint.clone();
    let deadline = started + options.deadline;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let result = runtime.block_on(async {
        let mut secret = [0; 32];
        secret[..8].copy_from_slice(&options.seed.wrapping_add(1).to_be_bytes());
        let (node, _) = tokio::time::timeout(
            remaining(deadline)?,
            bind_node(
                ([127, 0, 0, 1], 0).into(),
                Some(&secret),
                options.profile.node(),
                ConnectionBudget::default(),
                options.custom_relay.as_ref(),
            ),
        )
        .await
        .map_err(|_| "deadline exceeded while binding endpoint".to_string())?
        .map_err(|error| error.to_string())?;
        let node = Arc::new(node);
        let invitation = Invitation::from_bytes(&invitation).map_err(str::to_owned)?;
        let pending = PendingJoin::from_invitation(&invitation, &checkpoint, node.id(), "refusal")
            .map_err(str::to_owned)?;
        let request = pending.admission_request().map_err(str::to_owned)?.to_vec();
        let payload = packet(&request, "refusal", &checkpoint);
        tokio::time::timeout(
            remaining(deadline)?,
            node.add_address_hint(owner_data.peer, owner_data.address),
        )
        .await
        .map_err(|_| "deadline exceeded while adding address hint".to_string())?
        .map_err(|error| error.to_string())?;
        close_handle(owner_handle).await?;
        let request_result = request_control(&node, owner_data.peer, &payload, deadline).await;
        if request_result.is_ok() {
            close_node_before(node, deadline).await;
            return Err("refusal: request completed while owner was unavailable".into());
        }
        close_node_before(node, deadline).await;
        Ok::<_, String>((
            Outcome {
                refusals: 1,
                ..Outcome::default()
            },
            1,
            json!({"owner_closed": true, "refused": true}),
        ))
    });
    let _ = arachne_runtime::close(owner_handle);
    let (outcomes, peak_nodes, owner_metrics) = result?;
    let receipt = outcomes.receipt(&options, started.elapsed(), peak_nodes, owner_metrics);
    write_receipt(&options, &receipt)?;
    if !receipt["passed"].as_bool().unwrap_or(false) {
        return Err(receipt.to_string());
    }
    Ok(receipt)
}

fn write_receipt(options: &Options, receipt: &Value) -> Result<(), String> {
    if let Some(path) = &options.receipt {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(
            path,
            serde_json::to_vec_pretty(receipt).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn run_cancel(options: Options) -> Result<Value, String> {
    let started = Instant::now();
    let owner = create_owner(options.seed, options.profile, options.custom_relay.as_ref())?;
    let owner_handle = owner.handle;
    let owner_data = OwnerData {
        peer: owner.peer,
        address: owner.address,
    };
    let invitation = owner.invitation.clone();
    let checkpoint = owner.checkpoint.clone();
    let deadline = started + options.deadline;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let result = runtime.block_on(async {
        let mut secret = [0; 32];
        secret[..8].copy_from_slice(&options.seed.wrapping_add(1).to_be_bytes());
        let (node, _) = tokio::time::timeout(
            remaining(deadline)?,
            bind_node(
                ([127, 0, 0, 1], 0).into(),
                Some(&secret),
                options.profile.node(),
                ConnectionBudget::default(),
                options.custom_relay.as_ref(),
            ),
        )
        .await
        .map_err(|_| "deadline exceeded while binding endpoint".to_string())?
        .map_err(|error| error.to_string())?;
        let node = Arc::new(node);
        let result = cancel_join(
            Arc::clone(&node),
            owner_data,
            invitation,
            checkpoint,
            owner_handle,
            deadline,
        )
        .await;
        let mut nodes = vec![node];
        close_nodes(&mut nodes).await;
        result?;
        let owner_metrics = tokio::task::spawn_blocking(move || {
            call(owner_handle, json!({"op": "workspace_metrics"}))
        })
        .await
        .map_err(|error| error.to_string())??;
        Ok::<_, String>((
            Outcome {
                cancelled: 1,
                ..Outcome::default()
            },
            1,
            compact_metrics(&owner_metrics),
        ))
    });
    let _ = arachne_runtime::close(owner_handle);
    let (outcomes, peak_nodes, owner_metrics) = result?;
    let receipt = outcomes.receipt(&options, started.elapsed(), peak_nodes, owner_metrics);
    write_receipt(&options, &receipt)?;
    if !receipt["passed"].as_bool().unwrap_or(false) {
        return Err(receipt.to_string());
    }
    Ok(receipt)
}

fn run_restart(options: Options) -> Result<Value, String> {
    let started = Instant::now();
    let owner = create_owner(options.seed, options.profile, options.custom_relay.as_ref())?;
    let owner_handle = owner.handle;
    let owner_data = OwnerData {
        peer: owner.peer,
        address: owner.address,
    };
    let invitation = owner.invitation.clone();
    let checkpoint = owner.checkpoint.clone();
    let deadline = started + options.deadline;
    let seed = options.seed.wrapping_add(1);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let restarted = runtime.block_on(async {
        let mut secret = [0; 32];
        secret[..8].copy_from_slice(&seed.to_be_bytes());
        let (initial, _) = tokio::time::timeout(
            remaining(deadline)?,
            bind_node(
                ([127, 0, 0, 1], 0).into(),
                Some(&secret),
                options.profile.node(),
                ConnectionBudget::default(),
                options.custom_relay.as_ref(),
            ),
        )
        .await
        .map_err(|_| "deadline exceeded while binding initial endpoint".to_string())?
        .map_err(|error| error.to_string())?;
        let initial = Arc::new(initial);
        let parsed_invitation = Invitation::from_bytes(&invitation).map_err(str::to_owned)?;
        let pending = PendingJoin::from_invitation(
            &parsed_invitation,
            &checkpoint,
            initial.id(),
            "restarting",
        )
        .map_err(str::to_owned)?;
        let request = pending.admission_request().map_err(str::to_owned)?.to_vec();
        let payload = packet(&request, "restarting", &checkpoint);
        tokio::time::timeout(
            remaining(deadline)?,
            initial.add_address_hint(owner_data.peer, owner_data.address),
        )
        .await
        .map_err(|_| "deadline exceeded while adding initial address hint".to_string())?
        .map_err(|error| error.to_string())?;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            let _ = ready_tx.send(wait_for_work(owner_handle));
        });
        let cancellation = initial.control_cancellation();
        let requester = Arc::clone(&initial);
        let request_task =
            tokio::spawn(async move { requester.request_control(owner_data.peer, &payload).await });
        let ready = tokio::task::spawn_blocking(move || {
            ready_rx.recv_timeout(remaining(deadline).unwrap_or_default())
        })
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
        if !ready {
            cancellation.send_replace(true);
            request_task.abort();
            let _ = request_task.await;
            let _ = waiter.join();
            return Err("restart: owner work signal closed before queueing".into());
        }
        let queued = call(
            owner_handle,
            json!({"op": "poll_admission", "profile": false}),
        )?;
        if queued["state"] != "admission_queued" {
            cancellation.send_replace(true);
            request_task.abort();
            let _ = request_task.await;
            let _ = waiter.join();
            return Err(format!("restart: admission was not queued: {queued}"));
        }
        cancellation.send_replace(true);
        let request_result = request_task.await.map_err(|error| error.to_string())?;
        if let Err(error) = request_result
            && !matches!(error, arachne_node::Error::Cancelled)
        {
            let _ = waiter.join();
            return Err(format!("restart: initial request failed: {error}"));
        }
        waiter
            .join()
            .map_err(|_| "restart: owner wait thread panicked".to_string())?;
        let mut initial_nodes = vec![initial];
        close_nodes(&mut initial_nodes).await;

        let mut committed = Value::Null;
        while Instant::now() < deadline {
            committed = call(owner_handle, json!({"op": "drive_workspace"}))?;
            if committed["state"] == "workspace_committed" {
                break;
            }
            if committed.is_null() {
                return Err("restart: cancelled admission was not retained".into());
            }
        }
        if committed["state"] != "workspace_committed" {
            return Err("restart: admission did not commit before deadline".into());
        }

        let (restarted, _) = tokio::time::timeout(
            remaining(deadline)?,
            bind_node(
                ([127, 0, 0, 1], 0).into(),
                Some(&secret),
                options.profile.node(),
                ConnectionBudget::default(),
                options.custom_relay.as_ref(),
            ),
        )
        .await
        .map_err(|_| "deadline exceeded while binding restarted endpoint".to_string())?
        .map_err(|error| error.to_string())?;
        let restarted = Arc::new(restarted);
        tokio::time::timeout(
            remaining(deadline)?,
            restarted.add_address_hint(owner_data.peer, owner_data.address),
        )
        .await
        .map_err(|_| "deadline exceeded while adding restarted address hint".to_string())?
        .map_err(|error| error.to_string())?;
        Ok::<_, String>((restarted, pending))
    });
    let (node, pending) = match restarted {
        Ok(value) => value,
        Err(error) => {
            let _ = arachne_runtime::close(owner_handle);
            return Err(error);
        }
    };

    let done = Arc::new(AtomicUsize::new(0));
    let driver = spawn_owner_driver(owner_handle, 1, done.clone(), deadline);
    let result = runtime.block_on(async {
        let joined = full_join_with_pending(
            Arc::clone(&node),
            &owner_data,
            pending,
            "qualification-restart".into(),
            Scenario::Restart,
            started,
            deadline,
        )
        .await;
        let mut nodes = vec![node];
        close_nodes(&mut nodes).await;
        let owner_metrics = tokio::task::spawn_blocking(move || {
            call(owner_handle, json!({"op": "workspace_metrics"}))
        })
        .await
        .map_err(|error| error.to_string())??;
        let mut outcomes = Outcome::default();
        match joined {
            Ok((welcome, stage, profile, presence)) => {
                outcomes.welcome_ms.push(welcome);
                outcomes.stage_ms.push(stage);
                outcomes.profile_ms.push(profile);
                outcomes.presence_ms.push(presence);
            }
            Err(error) => outcomes.fail(&error),
        }
        done.fetch_add(1, Ordering::Release);
        Ok::<_, String>((outcomes, 1, compact_metrics(&owner_metrics)))
    });
    let _ = arachne_runtime::close(owner_handle);
    let driver_result = driver
        .join()
        .map_err(|_| "owner driver panicked".to_string())?;
    driver_result?;
    let (outcomes, peak_nodes, owner_metrics) = result?;
    let receipt = outcomes.receipt(&options, started.elapsed(), peak_nodes, owner_metrics);
    write_receipt(&options, &receipt)?;
    if !receipt["passed"].as_bool().unwrap_or(false) {
        return Err(receipt.to_string());
    }
    Ok(receipt)
}

fn run_partition(options: Options) -> Result<Value, String> {
    let started = Instant::now();
    let owner = create_owner(options.seed, options.profile, options.custom_relay.as_ref())?;
    let owner_handle = owner.handle;
    let owner_data = OwnerData {
        peer: owner.peer,
        address: owner.address,
    };
    let invitation = owner.invitation.clone();
    let checkpoint = owner.checkpoint.clone();
    let deadline = started + options.deadline;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let interrupted = runtime.block_on(async {
        let mut secret = [0; 32];
        secret[..8].copy_from_slice(&options.seed.wrapping_add(1).to_be_bytes());
        let (node, _) = tokio::time::timeout(
            remaining(deadline)?,
            bind_node(
                ([127, 0, 0, 1], 0).into(),
                Some(&secret),
                options.profile.node(),
                ConnectionBudget::default(),
                options.custom_relay.as_ref(),
            ),
        )
        .await
        .map_err(|_| "deadline exceeded while binding partition endpoint".to_string())?
        .map_err(|error| error.to_string())?;
        let node = Arc::new(node);
        let invitation = Invitation::from_bytes(&invitation).map_err(str::to_owned)?;
        let pending =
            PendingJoin::from_invitation(&invitation, &checkpoint, node.id(), "partition")
                .map_err(str::to_owned)?;
        let request = pending.admission_request().map_err(str::to_owned)?.to_vec();
        let payload = packet(&request, "partition", &checkpoint);
        tokio::time::timeout(
            remaining(deadline)?,
            node.add_address_hint(owner_data.peer, owner_data.address),
        )
        .await
        .map_err(|_| "deadline exceeded while adding partition address hint".to_string())?
        .map_err(|error| error.to_string())?;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            let _ = ready_tx.send(wait_for_work(owner_handle));
        });
        let requester = Arc::clone(&node);
        let request_task =
            tokio::spawn(async move { requester.request_control(owner_data.peer, &payload).await });
        let ready = tokio::task::spawn_blocking(move || {
            ready_rx.recv_timeout(remaining(deadline).unwrap_or_default())
        })
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
        if !ready {
            request_task.abort();
            let _ = request_task.await;
            let _ = close_handle(owner_handle).await;
            let _ = waiter.join();
            return Err("partition: owner work signal closed before request".into());
        }
        close_handle(owner_handle).await?;
        let request_result = request_task.await.map_err(|error| error.to_string())?;
        waiter
            .join()
            .map_err(|_| "partition: owner wait thread panicked".to_string())?;
        if request_result.is_ok() {
            close_node_before(node, deadline).await;
            return Err("partition: request completed after owner shutdown".into());
        }
        Ok::<_, String>((node, pending))
    });
    let (node, pending) = match interrupted {
        Ok(value) => value,
        Err(error) => {
            let _ = arachne_runtime::close(owner_handle);
            return Err(error);
        }
    };
    let restored = restore_owner(
        owner,
        options.seed,
        options.profile,
        options.custom_relay.as_ref(),
    )?;
    let restored_handle = restored.handle;
    let restored_data = OwnerData {
        peer: restored.peer,
        address: restored.address,
    };
    let done = Arc::new(AtomicUsize::new(0));
    let driver = spawn_owner_driver(restored_handle, 1, done.clone(), deadline);
    let result = runtime.block_on(async {
        tokio::time::timeout(
            remaining(deadline)?,
            node.add_address_hint(restored_data.peer, restored_data.address),
        )
        .await
        .map_err(|_| "deadline exceeded while adding restored owner hint".to_string())?
        .map_err(|error| error.to_string())?;
        let joined = full_join_with_pending(
            Arc::clone(&node),
            &restored_data,
            pending,
            "qualification-partition".into(),
            Scenario::Partition,
            started,
            deadline,
        )
        .await;
        close_node_before(node, deadline).await;
        let owner_metrics = tokio::task::spawn_blocking(move || {
            call(restored_handle, json!({"op": "workspace_metrics"}))
        })
        .await
        .map_err(|error| error.to_string())??;
        let mut outcomes = Outcome::default();
        match joined {
            Ok((welcome, stage, profile, presence)) => {
                outcomes.welcome_ms.push(welcome);
                outcomes.stage_ms.push(stage);
                outcomes.profile_ms.push(profile);
                outcomes.presence_ms.push(presence);
                outcomes.partitions_recovered = 1;
            }
            Err(error) => outcomes.fail(&error),
        }
        done.fetch_add(1, Ordering::Release);
        Ok::<_, String>((outcomes, 1, compact_metrics(&owner_metrics)))
    });
    let _ = arachne_runtime::close(restored_handle);
    let driver_result = driver
        .join()
        .map_err(|_| "owner driver panicked".to_string())?;
    driver_result?;
    let (outcomes, peak_nodes, owner_metrics) = result?;
    let receipt = outcomes.receipt(&options, started.elapsed(), peak_nodes, owner_metrics);
    write_receipt(&options, &receipt)?;
    if !receipt["passed"].as_bool().unwrap_or(false) {
        return Err(receipt.to_string());
    }
    Ok(receipt)
}

fn run_queue_pressure(options: Options) -> Result<Value, String> {
    let started = Instant::now();
    let owner = create_owner(options.seed, options.profile, options.custom_relay.as_ref())?;
    let owner_handle = owner.handle;
    let owner_data = OwnerData {
        peer: owner.peer,
        address: owner.address,
    };
    let invitation = owner.invitation.clone();
    let checkpoint = owner.checkpoint.clone();
    let deadline = started + options.deadline;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(16)
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let queued = runtime.block_on(async {
        let mut binds = JoinSet::new();
        for index in 0..options.endpoints {
            let seed = options.seed.wrapping_add(index as u64 + 1);
            let profile = options.profile.node();
            let relay = options.custom_relay.clone();
            binds.spawn(async move {
                let mut secret = [0; 32];
                secret[..8].copy_from_slice(&seed.to_be_bytes());
                let (node, _) = tokio::time::timeout(
                    remaining(deadline)?,
                    bind_node(
                        ([127, 0, 0, 1], 0).into(),
                        Some(&secret),
                        profile,
                        ConnectionBudget::default(),
                        relay.as_ref(),
                    ),
                )
                .await
                .map_err(|_| "deadline exceeded while binding queue-pressure endpoint".to_string())?
                .map_err(|error| error.to_string())?;
                Ok::<_, String>(Arc::new(node))
            });
        }
        let mut nodes = Vec::with_capacity(options.endpoints);
        while let Some(result) = binds.join_next().await {
            match result.map_err(|error| error.to_string())? {
                Ok(node) => nodes.push(node),
                Err(error) => {
                    close_nodes(&mut nodes).await;
                    return Err(error);
                }
            }
        }
        let parsed_invitation = Invitation::from_bytes(&invitation).map_err(str::to_owned)?;
        let mut pending = Vec::with_capacity(nodes.len());
        let mut requests = Vec::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            tokio::time::timeout(
                remaining(deadline)?,
                node.add_address_hint(owner_data.peer, owner_data.address),
            )
            .await
            .map_err(|_| "deadline exceeded while adding queue-pressure hint".to_string())?
            .map_err(|error| error.to_string())?;
            let pending_join = PendingJoin::from_invitation(
                &parsed_invitation,
                &checkpoint,
                node.id(),
                &format!("queue-pressure-{}", index + 1),
            )
            .map_err(str::to_owned)?;
            let request = pending_join
                .admission_request()
                .map_err(str::to_owned)?
                .to_vec();
            let payload = packet(
                &request,
                &format!("queue-pressure-{}", index + 1),
                &checkpoint,
            );
            let requester = Arc::clone(node);
            requests.push(tokio::spawn(async move {
                requester.request_control(owner_data.peer, &payload).await
            }));
            pending.push(pending_join);
        }
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            let _ = ready_tx.send(wait_for_work(owner_handle));
        });
        let ready = tokio::task::spawn_blocking(move || {
            ready_rx.recv_timeout(remaining(deadline).unwrap_or_default())
        })
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
        waiter
            .join()
            .map_err(|_| "queue-pressure: owner wait thread panicked".to_string())?;
        if !ready {
            for request in requests {
                request.abort();
                let _ = request.await;
            }
            close_nodes(&mut nodes).await;
            return Err("queue-pressure: owner work signal closed before intake".into());
        }

        // The work signal wakes the host; one native tick is what transfers
        // the transport packet into the bounded admission queue. Stop before
        // the owner driver drains it, then retry the same requests below.
        tokio::task::spawn_blocking(move || call(owner_handle, json!({"op": "drive_workspace"})))
            .await
            .map_err(|error| error.to_string())??;
        let metrics = tokio::task::spawn_blocking(move || {
            call(owner_handle, json!({"op": "workspace_metrics"}))
        })
        .await
        .map_err(|error| error.to_string())??;
        let queue_peak = metrics["admission_queue"].as_u64().unwrap_or_default() as usize;
        for request in requests {
            request.abort();
            let _ = request.await;
        }
        if queue_peak == 0 {
            close_nodes(&mut nodes).await;
            return Err("queue-pressure: owner queue never became non-empty".into());
        }
        Ok::<_, String>((nodes, pending, queue_peak))
    });
    let (mut nodes, pending, queue_peak) = match queued {
        Ok(value) => value,
        Err(error) => {
            let _ = arachne_runtime::close(owner_handle);
            return Err(error);
        }
    };

    let done = Arc::new(AtomicUsize::new(0));
    let driver = spawn_owner_driver(owner_handle, options.endpoints, done.clone(), deadline);
    let result = runtime.block_on(async {
        let mut joins = JoinSet::new();
        for (index, (node, pending)) in nodes.iter().zip(pending).enumerate() {
            let node = Arc::clone(node);
            let owner = owner_data;
            let name = format!("qualification-queue-pressure-{}", index + 1);
            joins.spawn(async move {
                full_join_with_pending(
                    node,
                    &owner,
                    pending,
                    name,
                    Scenario::QueuePressure,
                    started,
                    deadline,
                )
                .await
            });
        }
        let mut outcomes = Outcome {
            queue_peak,
            ..Outcome::default()
        };
        while let Some(result) = joins.join_next().await {
            match result.map_err(|error| error.to_string())? {
                Ok((welcome, stage, profile, presence)) => {
                    outcomes.welcome_ms.push(welcome);
                    outcomes.stage_ms.push(stage);
                    outcomes.profile_ms.push(profile);
                    outcomes.presence_ms.push(presence);
                }
                Err(error) => outcomes.fail(&error),
            }
            done.fetch_add(1, Ordering::Release);
        }
        let owner_metrics = tokio::task::spawn_blocking(move || {
            call(owner_handle, json!({"op": "workspace_metrics"}))
        })
        .await
        .map_err(|error| error.to_string())??;
        let peak_nodes = nodes.len();
        close_nodes(&mut nodes).await;
        Ok::<_, String>((outcomes, peak_nodes, compact_metrics(&owner_metrics)))
    });
    let _ = arachne_runtime::close(owner_handle);
    let driver_result = driver
        .join()
        .map_err(|_| "owner driver panicked".to_string())?;
    driver_result?;
    let (outcomes, peak_nodes, owner_metrics) = result?;
    let receipt = outcomes.receipt(&options, started.elapsed(), peak_nodes, owner_metrics);
    write_receipt(&options, &receipt)?;
    if !receipt["passed"].as_bool().unwrap_or(false) {
        return Err(receipt.to_string());
    }
    Ok(receipt)
}

fn spawn_owner_driver(
    owner_handle: i64,
    endpoints: usize,
    done: Arc<AtomicUsize>,
    deadline: Instant,
) -> thread::JoinHandle<Result<(), String>> {
    thread::spawn(move || {
        let mut presence_replies = 0;
        while done.load(Ordering::Acquire) < endpoints && Instant::now() < deadline {
            let woke = match wait_for_work(owner_handle) {
                Ok(woke) => woke,
                Err(error) => return Err(error),
            };
            if !woke {
                return Ok(());
            }
            // `wait_for_work` deliberately wakes the host to drain the native
            // queue. Calling it once per packet can leave retained replies
            // behind while every joiner is retrying, which makes a local run
            // look like a network timeout.
            loop {
                let value = match call(owner_handle, json!({"op":"drive_workspace"})) {
                    Ok(value) => value,
                    Err(error) => return Err(error),
                };
                let Some(state) = value.get("state").and_then(Value::as_str) else {
                    break;
                };
                let stop_after_presence = state == "presence_replied";
                if matches!(
                    state,
                    "workspace_committed" | "workspace_reply_ready" | "admission_queued"
                ) {
                    continue;
                }
                if stop_after_presence {
                    presence_replies += 1;
                    if presence_replies == endpoints {
                        return Ok(());
                    }
                    continue;
                }
                // Profile, presence, recovery, and nearby replies are all
                // valid work drained by this same Rust boundary.
                continue;
            }
        }
        Ok(())
    })
}

fn run(options: Options) -> Result<Value, String> {
    if matches!(options.scenario, Scenario::Refusal) {
        return run_refusal(options);
    }
    if matches!(options.scenario, Scenario::OwnerLoss) {
        return run_owner_loss(options);
    }
    if matches!(options.scenario, Scenario::Cancel) {
        return run_cancel(options);
    }
    if matches!(options.scenario, Scenario::Restart) {
        return run_restart(options);
    }
    if matches!(options.scenario, Scenario::Partition) {
        return run_partition(options);
    }
    if matches!(options.scenario, Scenario::QueuePressure) {
        return run_queue_pressure(options);
    }
    let started = Instant::now();
    let owner = create_owner(options.seed, options.profile, options.custom_relay.as_ref())?;
    let owner_data = OwnerData {
        peer: owner.peer,
        address: owner.address,
    };
    let owner_handle = owner.handle;
    let invitation = owner.invitation.clone();
    let checkpoint = owner.checkpoint.clone();
    let done = Arc::new(AtomicUsize::new(0));
    let deadline = started + options.deadline;
    let driver = spawn_owner_driver(owner_handle, options.endpoints, done.clone(), deadline);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(16)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let result = runtime.block_on(run_nodes(
        options.clone(),
        owner_data,
        owner_handle,
        owner.workspace,
        invitation,
        checkpoint,
        done.clone(),
        deadline,
    ));
    // Closing the owner wakes a driver parked in wait_for_work after the final
    // reply. The driver never owns application state; Rust runtime does.
    arachne_runtime::close(owner_handle)?;
    let driver_result = driver
        .join()
        .map_err(|_| "owner driver panicked".to_string())?;
    driver_result?;
    let (outcomes, peak_nodes, owner_metrics) = result?;
    let receipt = outcomes.receipt(&options, started.elapsed(), peak_nodes, owner_metrics);
    write_receipt(&options, &receipt)?;
    if !receipt["passed"].as_bool().unwrap_or(false) {
        return Err(receipt.to_string());
    }
    Ok(receipt)
}

fn command_arguments() -> Result<Vec<String>, String> {
    std::env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|_| "command arguments must be valid UTF-8".to_string())
        })
        .collect()
}

fn main() {
    let arguments = match command_arguments() {
        Ok(arguments) => arguments,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    let mut options = match Options::parse(arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    let local_relay = if matches!(options.relay_infrastructure, RelayInfrastructure::Local) {
        let loss_after =
            matches!(options.scenario, Scenario::RelayLoss).then_some(options.relay_loss_after);
        match LocalRelay::start(loss_after) {
            Ok(relay) => {
                options.custom_relay = Some(relay.options.clone());
                Some(relay)
            }
            Err(error) => {
                eprintln!("qualification failed: {error}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    let result = run(options);
    drop(local_relay);
    match result {
        Ok(receipt) => println!("{}", serde_json::to_string_pretty(&receipt).unwrap()),
        Err(error) => {
            eprintln!("qualification failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_reject_endpoint_counts_above_qualification_limit() {
        let error = Options::parse(["--endpoints".into(), "1001".into()]).unwrap_err();
        assert!(error.contains("between 1 and 1000"));
    }

    #[test]
    fn options_parse_profile_and_receipt() {
        let options = Options::parse([
            "--endpoints".into(),
            "500".into(),
            "--profile".into(),
            "relay".into(),
            "--receipt".into(),
            ".cache/receipt.json".into(),
        ])
        .unwrap();
        assert_eq!(options.endpoints, 500);
        assert_eq!(options.profile.label(), "relay");
        assert_eq!(options.scenario.label(), "baseline");
        assert_eq!(options.receipt, Some(PathBuf::from(".cache/receipt.json")));
    }

    #[test]
    fn options_parse_gossip_profile() {
        let options = Options::parse(["--profile".into(), "gossip".into()]).unwrap();
        assert_eq!(options.profile.label(), "gossip");
        assert!(matches!(options.profile.node(), NetworkProfile::Direct));
    }

    #[test]
    fn selectable_profiles_emit_bounded_path_receipts() {
        for profile in ["direct", "gossip", "relay"] {
            let options = Options::parse([
                "--endpoints".into(),
                "2".into(),
                "--profile".into(),
                profile.into(),
            ])
            .unwrap();
            let mut outcome = Outcome::default();
            outcome.welcome_ms = vec![1, 2];
            outcome.stage_ms = vec![1, 2];
            outcome.profile_ms = vec![1, 2];
            outcome.presence_ms = vec![1, 2];
            let receipt = outcome.receipt(&options, Duration::from_millis(1), 2, Value::Null);
            assert_eq!(receipt["profile"], profile);
            assert_eq!(
                receipt["relay_infrastructure"],
                if profile == "relay" {
                    "iroh_default_relays"
                } else {
                    "not_applicable"
                }
            );
            assert_eq!(receipt["real_iroh_endpoints"], 3);
            assert_eq!(receipt["phases"]["presence"]["completed"], 2);
            assert_eq!(receipt["classification"], "passed");
            assert!(
                receipt["evidence_ceiling"]
                    .as_str()
                    .unwrap()
                    .contains("real Rust/Iroh endpoints")
            );
        }
    }

    #[test]
    fn gossip_profile_rejects_unqualified_scenarios() {
        let error = Options::parse([
            "--profile".into(),
            "gossip".into(),
            "--scenario".into(),
            "restart".into(),
            "--endpoints".into(),
            "1".into(),
        ])
        .unwrap_err();
        assert!(error.contains("requires --scenario baseline"));
    }

    #[test]
    fn gossip_profile_requires_a_receiver() {
        let error = Options::parse([
            "--profile".into(),
            "gossip".into(),
            "--endpoints".into(),
            "1".into(),
        ])
        .unwrap_err();
        assert!(error.contains("requires at least 2 endpoints"));
    }

    #[test]
    fn options_parse_duplicate_scenario() {
        let options = Options::parse(["--scenario".into(), "duplicate".into()]).unwrap();
        assert_eq!(options.scenario.label(), "duplicate");
    }

    #[test]
    fn cancel_scenario_is_single_endpoint() {
        let error = Options::parse([
            "--scenario".into(),
            "cancel".into(),
            "--endpoints".into(),
            "2".into(),
        ])
        .unwrap_err();
        assert!(
            error.contains("cancel/restart/owner-loss/refusal/partition")
                && error.contains("--endpoints 1")
        );
    }

    #[test]
    fn options_parse_restart_scenario() {
        let options = Options::parse([
            "--scenario".into(),
            "restart".into(),
            "--endpoints".into(),
            "1".into(),
        ])
        .unwrap();
        assert_eq!(options.scenario.label(), "restart");
    }

    #[test]
    fn options_parse_owner_loss_scenario() {
        let options = Options::parse([
            "--scenario".into(),
            "owner-loss".into(),
            "--endpoints".into(),
            "1".into(),
        ])
        .unwrap();
        assert_eq!(options.scenario.label(), "owner-loss");
    }

    #[test]
    fn options_parse_refusal_scenario() {
        let options = Options::parse([
            "--scenario".into(),
            "refusal".into(),
            "--endpoints".into(),
            "1".into(),
        ])
        .unwrap();
        assert_eq!(options.scenario.label(), "refusal");
    }

    #[test]
    fn options_parse_partition_scenario() {
        let options = Options::parse([
            "--scenario".into(),
            "partition".into(),
            "--endpoints".into(),
            "1".into(),
        ])
        .unwrap();
        assert_eq!(options.scenario.label(), "partition");
    }

    #[test]
    fn options_parse_queue_pressure_scenario() {
        let options = Options::parse([
            "--scenario".into(),
            "queue-pressure".into(),
            "--endpoints".into(),
            "3".into(),
        ])
        .unwrap();
        assert_eq!(options.scenario.label(), "queue-pressure");
    }

    #[test]
    fn queue_pressure_requires_multiple_endpoints() {
        let error = Options::parse([
            "--scenario".into(),
            "queue-pressure".into(),
            "--endpoints".into(),
            "1".into(),
        ])
        .unwrap_err();
        assert!(error.contains("queue-pressure") && error.contains("at least 2"));
    }

    #[test]
    fn failure_receipts_use_bounded_classes() {
        assert_eq!(
            failure_class("transport: read error: connection lost"),
            "connection_loss"
        );
        assert_eq!(
            failure_class("control request not sent: connect"),
            "connect_failure"
        );
        assert_eq!(
            failure_class("deadline exceeded while binding endpoint"),
            "deadline"
        );
        assert_eq!(
            failure_class("unexpected private endpoint 127.0.0.1:99"),
            "operation_failure"
        );
    }

    #[test]
    fn compact_metrics_redacts_ids_and_bounds_route_labels() {
        let compact = compact_metrics(&json!({
            "paths": [
                {"member": vec![1u8; 32], "route": "direct", "rtt_ms": 4},
                {"member": vec![2u8; 32], "route": "relay", "rtt_ms": 8},
                {"member": vec![3u8; 32], "route": "private-address", "address": "127.0.0.1:9", "payload": "secret"},
                {"member": vec![4u8; 32], "route": "another-private-label"}
            ],
            "workspace": vec![5u8; 32],
            "session": vec![6u8; 32],
            "paths_limited": false
        }));

        assert_eq!(compact["paths"]["total"], 4);
        assert_eq!(compact["paths"]["by_route"]["direct"], 1);
        assert_eq!(compact["paths"]["by_route"]["relay"], 1);
        assert_eq!(compact["paths"]["by_route"]["custom"], 2);
        assert!(compact.get("workspace").is_none());
        assert!(compact.get("session").is_none());
        let serialized = serde_json::to_string(&compact).unwrap();
        for forbidden in [
            "\"member\"",
            "\"endpoint\"",
            "\"address\"",
            "\"invitation\"",
            "\"payload\"",
        ] {
            assert!(!serialized.contains(forbidden), "receipt leaked {forbidden}");
        }
        assert!(compact["paths"]["by_route"].as_object().unwrap().len() <= 3);
    }

    #[test]
    fn incomplete_phase_cannot_pass() {
        let options = Options::parse(["--endpoints".into(), "1".into()]).unwrap();
        let mut outcome = Outcome::default();
        outcome.presence_ms.push(1);
        let receipt = outcome.receipt(&options, Duration::from_millis(1), 1, Value::Null);
        assert!(!receipt["passed"].as_bool().unwrap());
        assert_eq!(receipt["classification"], "incomplete_or_protocol_failure");
    }

    #[test]
    fn capacity_receipts_are_distinguished_from_transport_failures() {
        let options = Options::parse(["--endpoints".into(), "2".into()]).unwrap();
        let mut outcome = Outcome::default();
        outcome.welcome_ms.push(1);
        let receipt = outcome.receipt(
            &options,
            Duration::from_millis(1),
            2,
            json!({
                "paths": {"limited": true},
                "connection_capacity": {"refused": 1}
            }),
        );
        assert_eq!(receipt["classification"], "capacity_saturated");
    }
}
