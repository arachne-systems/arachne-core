//! Portable blocking Arachne session runtime shared by native clients and language bindings.
//! No membership API is implied by creating an authenticated transport endpoint.
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use arachne_node::{
    AdmissionReport, ConnectionBudget, ControlClient, NetworkProfile, Node, Permissions,
    RelayOptions, Topic,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    runtime::Runtime,
    sync::{mpsc, watch},
};

mod client;
mod committed_view;
mod interest;
mod membership;

/// Wire-format helpers exposed ONLY for the capacity harness
/// (`tests/invitation_link_capacity.rs`). Not a stable API and not a
/// permission grant: these encode/decode DFMQ frames; all authorization
/// still happens at the receiving member.
#[doc(hidden)]
pub mod harness {
    pub use crate::membership::StateBasis;
    pub use crate::membership::wire::{Query, decode_reply, encode_query};
    pub use crate::presence::harness_presence_packet;
}
mod admission_waiters;
mod persistence;
pub(crate) mod presence;
mod protected;
mod resources;
mod work_signal;
mod workspace_activity;
pub use client::{
    AdmissionAuthorization, AdmissionReply, Client, ClientConfig, ConnectivityReport,
    ConnectionCapacityMetrics, ControlTimingMetrics, DeliveryFailure, DeliveryReport,
    DurationSummary, EndpointInfo, Error, ErrorKind, InterestObservation, InvitationDetails,
    InvitationInfo, JoinAdmissionStep, JoinRequest, MemberInfo, MemberKind,
    MembershipGossipMetrics, MemberRoster, Network, PeerPolicy, PeerRoute, Presence, Publication,
    PublicationCandidate, PublicationCurrent, ProtectedReceptionCandidate,
    ReceivedProtectedPublication,
    RecoveredPublication, RecoveryAdoption, RecoveryCandidate, RecoveryRangeReady,
    RecoveryRangeRequest, RecoveryRangeStatus, RecoveryStage, Result as ClientResult, RouteHint,
    RouteKind, WorkspaceCandidate, WorkspaceInfo, WorkspaceMetrics, WorkspaceState,
};
pub use persistence::{enable_record_storage, restore_record_storage, save_candidate};
pub use workspace_activity::{Activity as WorkspaceActivity, Phase as WorkspacePhase};

enum WorkspaceTransition {
    Recovery(
        Vec<(
            arachne_routing::PublicationContext,
            arachne_security::ApplicationMessage,
        )>,
    ),
    RoutedPublication(
        arachne_routing::PublicationContext,
        arachne_node::DeliveryClass,
        Vec<u8>,
        Vec<[u8; 32]>,
        Vec<[u8; 32]>,
    ),
    RoutedReception(
        arachne_routing::PublicationContext,
        arachne_security::ApplicationMessage,
        Vec<[u8; 32]>,
    ),
    Inbox,
    InboxRejected,
    InboxRecovery {
        count: usize,
    },
    DirectMiss {
        missing: u64,
    },
    CurrentView {
        cut: u64,
        pending: usize,
        stale: usize,
    },
    Admission,
    Management(arachne_security::ManagementAction, Vec<u8>),
    WorkspaceName,
    Invitation(
        Box<arachne_security::Invitation>,
        Vec<u8>,
        arachne_security::ManagementAction,
        Vec<u8>,
    ),
    Join,
    Publication(Vec<u8>),
    Reception(arachne_security::ApplicationMessage),
}

/// Durable Iroh-only routing state for one pending admission. A selected peer
/// means the request may already have left this endpoint, so retries stay on
/// that authenticated Iroh identity until it yields a retained result.
#[derive(Clone, Serialize, Deserialize)]
struct JoinLifecycle {
    peers: Vec<[u8; 32]>,
    selected: Option<[u8; 32]>,
    #[serde(default)]
    cursor: usize,
}

impl JoinLifecycle {
    fn new(peers: Vec<[u8; 32]>) -> Result<Self, String> {
        if peers.is_empty()
            || peers.len() > 3
            || peers.iter().any(|peer| peer.iter().all(|byte| *byte == 0))
            || peers.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err("join lifecycle requires one to three distinct Iroh peers".into());
        }
        Ok(Self {
            peers,
            selected: None,
            cursor: 0,
        })
    }

    fn validate(&self) -> Result<(), String> {
        if self.peers.is_empty()
            || self.peers.len() > 3
            || self.cursor > self.peers.len()
            || self
                .peers
                .iter()
                .any(|peer| peer.iter().all(|byte| *byte == 0))
            || self.peers.windows(2).any(|pair| pair[0] == pair[1])
            || self
                .selected
                .is_some_and(|peer| !self.peers.contains(&peer))
        {
            return Err("invalid persisted join lifecycle".into());
        }
        Ok(())
    }

    fn advance(&mut self) {
        self.selected = None;
        self.cursor = (self.cursor + 1) % self.peers.len();
    }
}

struct StagedWorkspace {
    publisher: Option<arachne_delivery::PublisherLog>,
    received: Option<arachne_delivery::receive::ReceiveJournal>,
    inbox: Option<arachne_delivery::inbox::ObjectInbox>,
    transition: WorkspaceTransition,
    workspace: arachne_security::Workspace,
    snapshot: Vec<u8>,
}

struct QueuedAdmission {
    checkpoint: Option<Vec<u8>>,
    display_name: Option<String>,
    approval_automatic: Option<bool>,
    validated: arachne_security::ValidatedAdmission,
}

struct PendingAdmissionApproval {
    attempt: arachne_security::AdmissionAttempt,
    queued: QueuedAdmission,
    delivered: bool,
    acknowledged: bool,
}

struct PendingControl<Q> {
    query: Q,
    peer: [u8; 32],
    task: tokio::task::JoinHandle<Result<Vec<u8>, arachne_node::Error>>,
}
impl<Q> Drop for PendingControl<Q> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

enum JoinAttemptOutcome {
    NotSent,
    Waiting,
    Reply {
        value: Value,
        history_prefix: Vec<Value>,
    },
    Failed(String),
}

struct PendingJoinExchange {
    peer: [u8; 32],
    task: tokio::task::JoinHandle<JoinAttemptOutcome>,
}
impl Drop for PendingJoinExchange {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct PendingCheckpointExchange {
    peer: [u8; 32],
    task: tokio::task::JoinHandle<Result<Value, String>>,
}
impl Drop for PendingCheckpointExchange {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct ReadyRange {
    query: arachne_delivery::RangeQuery,
    peer: [u8; 32],
    reply: Vec<u8>,
    packet_count: usize,
    automatic: bool,
}

struct ReadyDirectRange {
    query: arachne_delivery::wire::DirectRangeQuery,
    peer: [u8; 32],
    reply: Vec<u8>,
    packet_count: usize,
}

struct ReadyCurrentView {
    query: arachne_delivery::current::CurrentViewQuery,
    peer: [u8; 32],
    reply: Vec<u8>,
    cut: u64,
    value_count: usize,
}

type RecoveryReply = ([u8; 32], Result<Vec<u8>, String>);

struct PendingRange {
    query: arachne_delivery::RangeQuery,
    available: Option<arachne_delivery::wire::AvailableRangeQuery>,
    automatic: bool,
    replies: mpsc::Receiver<RecoveryReply>,
    task: tokio::task::JoinHandle<()>,
    attempted: usize,
    reason: Option<String>,
}
impl Drop for PendingRange {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct PendingDirectRange {
    query: arachne_delivery::wire::DirectRangeQuery,
    replies: mpsc::Receiver<RecoveryReply>,
    task: tokio::task::JoinHandle<()>,
    attempted: usize,
    reason: Option<String>,
}
impl Drop for PendingDirectRange {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct PendingCurrentView {
    query: arachne_delivery::current::CurrentViewQuery,
    automatic: bool,
    replies: mpsc::Receiver<RecoveryReply>,
    task: tokio::task::JoinHandle<()>,
    attempted: usize,
    reason: Option<String>,
    best: Option<ReadyCurrentView>,
}
impl Drop for PendingCurrentView {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Session {
    resources: resources::Jobs,
    presence: presence::Presence,
    interests: interest::Updates,
    records: Option<persistence::NativeStore>,
    membership_update: Option<PendingControl<membership::StateBasis>>,
    membership_offer: Option<PendingControl<u64>>,
    membership_offer_requires_adoption: bool,
    /// Last failed membership query per peer, for the peer-choice cooldown.
    membership_peer_failures: BTreeMap<[u8; 32], std::time::Instant>,
    /// The staged candidate came from a peer's step, not a local commit.
    staged_step_received: bool,
    /// Gossiped steps that skip ahead of this node's epoch, keyed by the
    /// epoch they extend. Bounded; applied in order as earlier steps land.
    gossip_steps_ahead: BTreeMap<u64, Vec<u8>>,
    /// The newest epoch heard by gossip or presence, and members that have it
    /// (ADR 0009). A hint only: the steps are pulled and verified.
    membership_head: Option<(u64, Vec<[u8; 32]>)>,
    /// One range pull toward `membership_head`, keyed by the epoch it extends.
    range_pull: Option<PendingControl<u64>>,
    /// Membership gossip outcomes, for workspace_metrics (ADR 0008).
    gossip_counts: Arc<membership::GossipCounts>,
    /// One page pull of a peer's retained names, and the peer sets already
    /// walked to the end (peer -> its profile digest), bounded.
    profile_pull: Option<PendingControl<membership::ProfilePull>>,
    profiles_walked: BTreeMap<[u8; 32], [u8; 32]>,
    /// Gossiped profiles of members not yet in this roster (bounded).
    gossip_profiles_pending: std::collections::VecDeque<Vec<u8>>,
    cutoff: Option<PendingControl<arachne_delivery::wire::CutoffQuery>>,
    current_view: Option<PendingCurrentView>,
    ready_current_view: Option<ReadyCurrentView>,
    range: Option<PendingRange>,
    ready_range: Option<ReadyRange>,
    direct_range: Option<PendingDirectRange>,
    ready_direct_range: Option<ReadyDirectRange>,
    direct_miss: Option<arachne_delivery::wire::DirectRangeQuery>,
    recovered: VecDeque<(
        arachne_routing::PublicationContext,
        arachne_security::ApplicationMessage,
    )>,
    publisher: Option<arachne_delivery::PublisherLog>,
    received: Option<arachne_delivery::receive::ReceiveJournal>,
    inbox: Option<arachne_delivery::inbox::ObjectInbox>,
    inbound_admission: Option<arachne_node::ControlRequest>,
    admission_queue: arachne_security::AdmissionQueue,
    admission_metadata: BTreeMap<[u8; 32], QueuedAdmission>,
    admission_waiters: admission_waiters::AdmissionWaiters<arachne_node::ControlRequest>,
    admission_pushes: Vec<PendingControl<[u8; 32]>>,
    pending_approvals: BTreeMap<[u8; 32], PendingAdmissionApproval>,
    staged_approval_id: Option<[u8; 32]>,
    // The bounded set of queued membership transitions handed to the durable
    // stage/adopt boundary; retained replies remain independently retryable.
    queued_admission_in_flight: Vec<arachne_security::AdmissionAttempt>,
    // Forced-progress trigger for batch staging: admission packets read since
    // the last staging attempt. Duplicate retries can keep the inbox non-empty
    // for ever; a count of reads ends that without waiting on a clock.
    admission_reads_since_stage: usize,
    nearby_workspaces: BTreeMap<[u8; 32], Vec<u8>>,
    nearby_identity: Option<String>,
    staged_workspace: Option<StagedWorkspace>,
    /// Retained member profiles, shared with the inquiry responder.
    profiles: membership::Profiles,
    peer_profile_summaries: BTreeMap<[u8; 32], [u8; 32]>,
    staged_removal: Option<(arachne_security::RemovedMembership, Vec<u8>)>,
    /// The committed workspace. Shared and never edited in place: a transition
    /// works on a provisional copy, and `commit_workspace` replaces this.
    workspace: Option<Arc<arachne_security::Workspace>>,
    /// The same state, published for inquiries answered without the host.
    committed: committed_view::Published,
    pending_join: Option<arachne_security::PendingJoin>,
    join_lifecycle: Option<JoinLifecycle>,
    checkpoint_exchange: Option<PendingCheckpointExchange>,
    join_exchange: Option<PendingJoinExchange>,
    activity: WorkspaceActivity,
    /// History this session already fetched for the pending join, beyond the
    /// last rollover boundary the host still carries. Untrusted until
    /// `StageJoin` replays it through the verifier from the pinned checkpoint.
    join_history_prefix: Vec<Value>,
    storage_key: Option<arachne_security::StorageKey>,
    overlay_paths: usize,
    node: Node,
    receiver: arachne_node::MessageReceiver,
    runtime: Runtime,
}

struct Registry {
    next: i64,
    sessions: BTreeMap<i64, SharedSession>,
    // Kept outside the session mutex: a parked host never blocks `execute`.
    signals: BTreeMap<i64, Arc<work_signal::WorkSignal>>,
    cancellations: BTreeMap<i64, watch::Sender<bool>>,
    connection_budget: ConnectionBudget,
}

type SharedSession = Arc<Mutex<Option<Session>>>;

// ponytail: Startup is serialized and capped at eight sessions; replace the registry
// with owned sessions when the secured capacity harness requires more. Data operations take only
// their session lock; a slow peer cannot hold the global registry during fanout.
static REGISTRY: std::sync::LazyLock<Mutex<Registry>> = std::sync::LazyLock::new(|| {
    Mutex::new(Registry {
        next: 1,
        sessions: BTreeMap::new(),
        signals: BTreeMap::new(),
        cancellations: BTreeMap::new(),
        connection_budget: ConnectionBudget::default(),
    })
});
const MAX_DEVICE_OVERLAY_PATHS: usize = 24;
const MAX_WORKSPACE_OVERLAY_PATHS: usize = 5;
const NEARBY_INVITATION: &[u8; 5] = b"DFNI\x01";
const NEARBY_WORKSPACE: &[u8; 5] = b"DFNW\x01";
const NEARBY_WORKSPACE_LIST: &[u8; 5] = b"DFNW\x02";
const NEARBY_IDENTITY: &[u8; 5] = b"DFND\x01";
const ADMISSION_RESULT_OFFER: &[u8; 5] = b"DFAR\x01";
const MAX_NEARBY_WORKSPACES: usize = 16;
// JSON commit/authorization arrays must fit both the 32 KiB membership offer
// request and the 128 KiB admission reply. The lower MLS seam supports 128;
// this transport adapter deliberately uses the smaller safe batch.
const MAX_RUNTIME_ADMISSION_BATCH: usize = 16;
// Half of the 512 control-exchange reserve (arachne-node budget.rs). Presence,
// profile and recovery exchanges always keep the other half.
const MAX_ADMISSION_WAITERS: usize = 256;
static DEVICE_OVERLAY_PATHS: AtomicUsize = AtomicUsize::new(0);

/// Stable host-facing vocabulary for the admission lifecycle.
pub mod admission_state {
    pub const QUEUED: &str = "admission_queued";
    pub const APPROVAL_PENDING: &str = "approval_pending";
    pub const APPROVAL_REQUESTED: &str = "approval_requested";
    pub const REPLIED: &str = "admission_replied";
    pub const UNAVAILABLE: &str = "admission_unavailable";
    pub const RECOVERY_REQUIRED: &str = "admission_recovery_required";
    pub const MEMBER_ALREADY_ADMITTED: &str = "member_already_admitted";
    pub const RECOVERY_REMOVE_AND_REINVITE: &str = "remove_and_reinvite";
    pub const NOT_SENT: &str = "admission_not_sent";
    /// The request was sent and the exchange ended with no reply. Ask again at
    /// once: the result may already be retained.
    pub const WAITING: &str = "admission_waiting";
}

fn transition_activity(
    session: &mut Session,
    phase: WorkspacePhase,
    reason: Option<&str>,
) -> Result<(), String> {
    session.activity.transition(phase, reason)
}

fn activity_value(session: &Session) -> Value {
    session.activity.projection()
}

fn nearby_workspace_key(workspace: Option<[u8; 32]>, invitation: &[u8]) -> [u8; 32] {
    workspace
        .or_else(|| {
            arachne_security::Invitation::from_bytes(invitation)
                .ok()
                .map(|value| value.workspace_id())
        })
        .unwrap_or_else(|| Sha256::digest(invitation).into())
}

fn nearby_workspace_reply(advertisements: &BTreeMap<[u8; 32], Vec<u8>>) -> Vec<u8> {
    match advertisements.len() {
        0 => Vec::new(),
        1 => advertisements.values().next().cloned().unwrap_or_default(),
        count => {
            let mut reply = NEARBY_WORKSPACE_LIST.to_vec();
            reply.push(count as u8);
            for payload in advertisements.values() {
                reply.extend((payload.len() as u16).to_be_bytes());
                reply.extend(payload);
            }
            reply
        }
    }
}

fn nearby_workspace_payloads(reply: &[u8]) -> Vec<&[u8]> {
    if reply.is_empty() {
        return Vec::new();
    }
    if !reply.starts_with(NEARBY_WORKSPACE_LIST) {
        return vec![reply];
    }
    let Some(&count) = reply.get(NEARBY_WORKSPACE_LIST.len()) else {
        return Vec::new();
    };
    if count == 0 || count as usize > MAX_NEARBY_WORKSPACES {
        return Vec::new();
    }
    let mut offset = NEARBY_WORKSPACE_LIST.len() + 1;
    let mut payloads = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Some(length) = reply.get(offset..offset + 2) else {
            return Vec::new();
        };
        let length = u16::from_be_bytes([length[0], length[1]]) as usize;
        offset += 2;
        if length == 0 || length > 4096 || offset + length > reply.len() {
            return Vec::new();
        }
        payloads.push(&reply[offset..offset + length]);
        offset += length;
    }
    if offset != reply.len() {
        return Vec::new();
    }
    payloads
}

/// Create an endpoint session. Credentials must be unique to this workspace-facing endpoint.
/// Blocking: invoke outside an async runtime. Call `close` to release its resources.
pub fn create(secret: Option<&[u8; 32]>) -> Result<i64, String> {
    create_endpoint(secret, NetworkProfile::Direct, None)
}

/// Opt in to local endpoint advertisement and lookup. No public discovery or relay.
/// Uses the supplied workspace-scoped identity; discovery does not grant membership.
pub fn create_lan(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NetworkProfile::Lan, None)
}

/// Advertise a device-level nearby-invitation endpoint on the local network.
pub fn create_nearby(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NetworkProfile::Nearby, None)
}

/// Opt in to Iroh's public Pkarr lookup and relay network, with LAN discovery
/// retained as a local fallback. External services provide routes, not authority.
pub fn create_wan(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NetworkProfile::Wan, None)
}

/// Force Iroh relay paths for a diagnostic WAN check while preserving the
/// caller's network connection and workspace-scoped endpoint identity.
pub fn create_relay(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NetworkProfile::RelayOnly, None)
}

/// Use a caller-supplied relay map for controlled qualification or an
/// operator-managed relay deployment.
pub fn create_relay_with_options(secret: &[u8; 32], relay: RelayOptions) -> Result<i64, String> {
    create_endpoint(Some(secret), NetworkProfile::RelayOnly, Some(relay))
}

/// Use public endpoint lookup without LAN discovery or saved address hints.
/// Direct Iroh paths remain enabled for a diagnostic WAN check.
pub fn create_wan_only(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NetworkProfile::WanOnly, None)
}

/// Create a Tor-only endpoint using the supplied stable endpoint identity.
#[cfg(feature = "tor")]
pub fn create_tor(secret: &[u8; 32]) -> Result<i64, String> {
    create_endpoint(Some(secret), NetworkProfile::Tor, None)
}

fn create_endpoint(
    secret: Option<&[u8; 32]>,
    profile: NetworkProfile,
    relay: Option<RelayOptions>,
) -> Result<i64, String> {
    let mut registry = REGISTRY.lock().map_err(|_| "node registry unavailable")?;
    if registry.sessions.len() >= 8 || registry.next == i64::MAX {
        return Err("node limit reached".into());
    }
    let connection_budget = registry.connection_budget.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let (node, receiver) = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                let address = ([0, 0, 0, 0], 0).into();
                let bound = match relay {
                    Some(relay) => {
                        Node::bind_with_profile_and_relay(
                            address,
                            secret,
                            profile,
                            connection_budget,
                            relay,
                        )
                        .await?
                    }
                    None => {
                        Node::bind_with_profile(address, secret, profile, connection_budget).await?
                    }
                };
                if matches!(profile, NetworkProfile::RelayOnly) {
                    bound.0.wait_online().await;
                }
                Ok::<_, arachne_node::Error>(bound)
            })
            .await
        })
        .map_err(|_| "node startup timed out")?
        .map_err(|e| e.to_string())?;
    let handle = registry.next;
    registry.next += 1;
    let signal = Arc::new(work_signal::WorkSignal::default());
    let committed = committed_view::Published::new(Some(Arc::clone(&signal)));
    node.set_inquiry_responder(committed.responder());
    let arrivals = node.control_signal();
    let forward = Arc::clone(&signal);
    // Ends with the runtime at close. It only forwards; it holds no session state.
    runtime.spawn(async move {
        loop {
            arrivals.notified().await;
            forward.raise();
        }
    });
    registry.signals.insert(handle, signal);
    registry
        .cancellations
        .insert(handle, node.control_cancellation());
    let presence = presence::Presence::new()?;
    registry.sessions.insert(
        handle,
        Arc::new(Mutex::new(Some(Session {
            resources: resources::Jobs::default(),
            presence,
            interests: interest::Updates::default(),
            records: None,
            membership_update: None,
            membership_offer: None,
            membership_offer_requires_adoption: false,
            membership_peer_failures: BTreeMap::new(),
            staged_step_received: false,
            gossip_steps_ahead: BTreeMap::new(),
            membership_head: None,
            range_pull: None,
            gossip_counts: Arc::default(),
            profile_pull: None,
            profiles_walked: BTreeMap::new(),
            gossip_profiles_pending: Default::default(),
            cutoff: None,
            current_view: None,
            ready_current_view: None,
            range: None,
            ready_range: None,
            direct_range: None,
            ready_direct_range: None,
            direct_miss: None,
            recovered: VecDeque::new(),
            publisher: None,
            received: None,
            inbox: None,
            inbound_admission: None,
            admission_queue: arachne_security::AdmissionQueue::new(),
            admission_metadata: BTreeMap::new(),
            admission_waiters: admission_waiters::AdmissionWaiters::new(MAX_ADMISSION_WAITERS),
            admission_pushes: Vec::new(),
            pending_approvals: BTreeMap::new(),
            staged_approval_id: None,
            queued_admission_in_flight: Vec::new(),
            admission_reads_since_stage: 0,
            nearby_workspaces: BTreeMap::new(),
            nearby_identity: None,
            staged_workspace: None,
            staged_removal: None,
            profiles: committed.profiles(),
            peer_profile_summaries: BTreeMap::new(),
            workspace: None,
            committed,
            pending_join: None,
            join_lifecycle: None,
            checkpoint_exchange: None,
            join_exchange: None,
            activity: WorkspaceActivity::default(),
            join_history_prefix: Vec::new(),
            storage_key: secret
                .map(arachne_security::StorageKey::derive)
                .transpose()
                .map_err(str::to_owned)?,
            overlay_paths: 0,
            node,
            receiver,
            runtime,
        }))),
    );
    Ok(handle)
}

/// The one place a workspace becomes the committed one. Callers have already
/// saved and adopted it; publishing here is what lets inquiries see it.
fn commit_workspace(session: &mut Session, workspace: arachne_security::Workspace) {
    let workspace = Arc::new(workspace);
    session
        .committed
        .publish(workspace.clone(), session.node.id());
    session.workspace = Some(workspace);
    // Any committed workspace change, including a name-only update, must be
    // advertised on the next native presence drain.  Otherwise peers keep
    // querying the old head until the periodic refresh interval elapses.
    session.presence.announce_next();
    // Names held for members this step admits (ADR 0008).
    membership::retain_held_profiles(session);
}

fn session(handle: i64) -> Result<SharedSession, String> {
    REGISTRY
        .lock()
        .map_err(|_| "node registry unavailable")?
        .sessions
        .get(&handle)
        .cloned()
        .ok_or_else(|| "invalid or closed node handle".into())
}

/// Return endpoint metadata for a live session.
pub fn describe(handle: i64) -> Result<String, String> {
    let shared = session(handle)?;
    let guard = shared.lock().map_err(|_| "node session unavailable")?;
    let session = guard.as_ref().ok_or("node is closed")?;
    Ok(json!({
        "endpoint_key": session.node.id(),
        "bound_address": session.node.address().to_string(),
        "workspace_ready": session.workspace.is_some(),
        "activity": activity_value(session),
    })
    .to_string())
}

/// Stop a session and release its transport, tasks and runtime.
pub fn close(handle: i64) -> Result<(), String> {
    let (shared, signal, cancellation) = {
        let mut registry = REGISTRY.lock().map_err(|_| "node registry unavailable")?;
        let shared = registry
            .sessions
            .remove(&handle)
            .ok_or("invalid or closed node handle")?;
        (
            shared,
            registry.signals.remove(&handle),
            registry.cancellations.remove(&handle),
        )
    };
    if let Some(cancellation) = cancellation {
        cancellation.send_replace(true);
    }
    if let Some(signal) = signal {
        signal.close();
    }
    // A lookup racing with close sees either the prior admitted operation or None.
    let session = shared
        .lock()
        .map_err(|_| "node session unavailable")?
        .take();
    // A removed membership has already shut down its owner. Release its registry
    // handle normally; a second close still rejects the missing handle.
    session.map(shutdown_session).unwrap_or(Ok(()))
}

/// Interrupt outbound control exchanges. The owner still calls `close` to
/// release the endpoint once its serial JNI request returns.
pub fn cancel(handle: i64) -> Result<(), String> {
    let cancellation = REGISTRY
        .lock()
        .map_err(|_| "node registry unavailable")?
        .cancellations
        .get(&handle)
        .cloned()
        .ok_or("invalid or closed node handle")?;
    cancellation.send_replace(true);
    Ok(())
}

/// Park the calling thread until this session may have work, without holding the
/// session lock. `Ok(true)`: drain with `poll_admission` until it returns null,
/// then call again. `Ok(false)`: the session closed. Spurious `true` is allowed.
pub fn wait_for_work(handle: i64) -> Result<bool, String> {
    let signal = REGISTRY
        .lock()
        .map_err(|_| "node registry unavailable")?
        .signals
        .get(&handle)
        .cloned()
        .ok_or("invalid or closed node handle")?;
    Ok(signal.wait())
}

fn shutdown_session(mut session: Session) -> Result<(), String> {
    release_overlay_paths(&DEVICE_OVERLAY_PATHS, session.overlay_paths);
    session.overlay_paths = 0;
    session.presence.cancel();
    session.interests.cancel();
    drop(session.join_exchange.take());
    drop(session.checkpoint_exchange.take());
    drop(session.cutoff.take());
    drop(session.current_view.take());
    session.ready_current_view = None;
    drop(session.range.take());
    session.resources = resources::Jobs::default();
    let result = session.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), session.node.close()).await
    });
    session.runtime.shutdown_timeout(Duration::from_secs(2));
    result.map_err(|_| "node shutdown timed out".into())
}

fn reserve_overlay_paths(total: &AtomicUsize, additional: usize) -> bool {
    total
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current
                .checked_add(additional)
                .filter(|next| *next <= MAX_DEVICE_OVERLAY_PATHS)
        })
        .is_ok()
}

fn release_overlay_paths(total: &AtomicUsize, count: usize) {
    if count != 0 {
        let previous = total.fetch_sub(count, Ordering::AcqRel);
        debug_assert!(previous >= count);
    }
}

async fn install_gossip_policy(
    node: &Node,
    reserved: &mut usize,
    workspace: [u8; 32],
    revision: u64,
    policy: BTreeMap<[u8; 32], Permissions>,
) -> Result<(), String> {
    let desired = policy
        .keys()
        .filter(|peer| **peer != node.id())
        .count()
        .min(MAX_WORKSPACE_OVERLAY_PATHS);
    let additional = desired.saturating_sub(*reserved);
    if !reserve_overlay_paths(&DEVICE_OVERLAY_PATHS, additional) {
        return Err("device overlay path limit reached".into());
    }
    let result = async {
        node.install_verified_policy(workspace, revision, policy)
            .await
            .map_err(|error| error.to_string())?;
        node.enable_gossip(workspace, revision)
            .await
            .map_err(|error| error.to_string())
    }
    .await;
    if let Err(error) = result {
        release_overlay_paths(&DEVICE_OVERLAY_PATHS, additional);
        return Err(error);
    }
    if *reserved > desired {
        release_overlay_paths(&DEVICE_OVERLAY_PATHS, *reserved - desired);
    }
    *reserved = desired;
    Ok(())
}

/// Queued control requests scanned for a range pull on each poll.
const RANGE_SCAN_DEPTH: usize = 64;

/// Maximum JSON request or metadata size in bytes.
pub const MAX_REQUEST: usize = 128 * 1024;

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentPublication {
    selector: [u8; 32],
    replacement_key: [u8; 32],
    expires_at: u64,
    #[serde(default)]
    tombstone: bool,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Resource {
        request: resources::Request,
    },
    WorkspaceMetrics {},
    WorkspaceState {},
    ResetWorkspace {},
    DiscardWorkspaceCandidate {},
    NetworkChange {},
    NearbyEndpoints {},
    SetNearbyIdentity {
        name: String,
    },
    NearbyWorkspaces {},
    SetNearbyWorkspace {
        mode: Option<String>,
        #[serde(default)]
        invitation: Vec<u8>,
        #[serde(default)]
        workspace_name: Option<String>,
        #[serde(default)]
        workspace: Option<[u8; 32]>,
    },
    SendNearbyInvitation {
        peer: [u8; 32],
        invitation: Vec<u8>,
    },
    PollWorkspacePresence {
        #[serde(default)]
        announce: bool,
    },
    FetchMembershipUpdate {
        peer: [u8; 32],
        #[serde(default)]
        replace_pending: bool,
    },
    PollMembershipUpdate {},
    NextMembershipPeer {
        after: Option<[u8; 32]>,
    },
    OfferMembershipUpdate {
        peer: [u8; 32],
        after: u64,
    },
    OfferStagedMembershipUpdate {
        peer: [u8; 32],
    },
    PollMembershipOffer {},
    FetchRecoveryRange {
        #[serde(default)]
        peer: Option<[u8; 32]>,
        #[serde(default)]
        author: Option<[u8; 32]>,
        revision: u64,
        topics: Vec<String>,
        #[serde(default)]
        after: Option<u64>,
        #[serde(default)]
        through: Option<u64>,
    },
    PollRecoveryRange {},
    NextDirectGap {},
    FetchDirectRecovery {
        author: [u8; 32],
        revision: u64,
        topic: String,
        recipients: Vec<[u8; 32]>,
        after: u64,
        through: u64,
    },
    PollDirectRecovery {},
    StageDirectRecovery {},
    StageDirectMiss {},
    CancelDirectRecovery {},
    StageRecoveryRange {
        #[serde(default)]
        retain_until: u64,
    },
    AdoptRecovery {
        #[serde(default)]
        snapshot: Vec<u8>,
    },
    PollRecoveredPublication {},
    CancelRecoveryRange {},
    PollRecoveryCutoff {},
    DiscoverRecoveryCutoff {
        peer: [u8; 32],
        revision: u64,
        topics: Vec<String>,
    },
    FetchCurrentView {
        #[serde(default)]
        peer: Option<[u8; 32]>,
        authority: [u8; 32],
        revision: u64,
        topic: String,
        selector: [u8; 32],
    },
    PollCurrentView {},
    StageCurrentView {},
    AdoptCurrentView {
        #[serde(default)]
        snapshot: Vec<u8>,
    },
    CancelCurrentView {},
    FetchInvitationCheckpoint {
        #[serde(default)]
        peer: Option<[u8; 32]>,
        #[serde(default)]
        peers: Vec<[u8; 32]>,
        invitation: Vec<u8>,
    },
    #[serde(rename = "request_admission")]
    JoinViaPeer {
        peer: [u8; 32],
    },
    StageNetworkPublication {
        revision: u64,
        topic: String,
        id: [u8; 16],
        payload: Vec<u8>,
        /// Empty is a normal topic publication. A nonempty scope contains
        /// canonical workspace member identities for a direct publication.
        #[serde(default)]
        recipients: Vec<[u8; 32]>,
        #[serde(default)]
        current: Option<CurrentPublication>,
        #[serde(default)]
        bulk: bool,
    },
    EnableObjectDelivery {},
    PollPendingObject {
        #[serde(default)]
        deferred: Vec<arachne_delivery::inbox::DeferredDeliveryStream>,
    },
    StageObjectAcknowledgement {
        member: [u8; 32],
        topic: String,
        counter: u64,
        id: [u8; 16],
    },
    StageObjectRejection {
        member: [u8; 32],
        topic: String,
        counter: u64,
        id: [u8; 16],
    },
    PollProtected {},
    EndpointInfo {},
    /// One control request to a peer by endpoint key, with an optional
    /// address hint; returns the peer's reply bytes. No workspace authority is
    /// involved. Used by the debug rig link to dial its controller.
    ControlExchange {
        peer: [u8; 32],
        address: Option<String>,
        payload: Vec<u8>,
    },
    StagePublication {
        context: Vec<u8>,
        payload: Vec<u8>,
    },
    AdoptPublication {
        #[serde(default)]
        snapshot: Vec<u8>,
    },
    StageReception {
        context: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    AdoptReception {
        #[serde(default)]
        snapshot: Vec<u8>,
    },
    PollAdmission {
        /// Report owner-side intake measurement alongside the usual state.
        /// Off by default so the reply shape is unchanged for every caller
        /// that has not asked for it.
        #[serde(default)]
        profile: bool,
    },
    /// Drive one ordered workspace transition. With native record storage,
    /// Rust persists and adopts its candidate before answering a peer; hosts
    /// receive only the resulting projection.
    DriveWorkspace {},
    ListAdmissionApprovals {
        #[serde(default)]
        after: Option<[u8; 32]>,
        #[serde(default)]
        limit: Option<usize>,
    },
    AcknowledgeAdmissionApproval {
        attempt_id: [u8; 32],
    },
    SendAdmissionReply {},
    StageJoin {
        commits: Vec<JoinStep>,
        #[serde(default)]
        welcome: Vec<u8>,
    },
    AdoptJoin {
        #[serde(default)]
        snapshot: Vec<u8>,
    },
    // Trusted host seam only: endpoint must come from authenticated transport.
    StageAdmission {
        authenticated_endpoint: [u8; 32],
        request: Vec<u8>,
    },
    MemberRoster {
        #[serde(default)]
        profiles: Vec<Vec<u8>>,
    },
    UseServiceProfile {},
    LeaveViaPeer {
        peer: [u8; 32],
    },
    StageSoloLeave {},
    StageManagement {
        action: WireManagement,
    },
    StageInvitation {
        expires_at: u64,
        personal: bool,
        #[serde(default)]
        automatic: bool,
        #[serde(default)]
        request_access: bool,
    },
    StageInvitationApproval {
        request: Vec<u8>,
        #[serde(default)]
        attempt_id: Option<[u8; 32]>,
    },
    StageInvitationDecline {
        request: Vec<u8>,
        #[serde(default)]
        attempt_id: Option<[u8; 32]>,
    },
    InvitationControls {},
    StageWorkspaceName {
        workspace_name: String,
    },
    StageWorkspaceNameUpdate {
        name_record: Vec<u8>,
    },
    StageWorkspaceNameCheckpoint {
        name_checkpoint: Vec<u8>,
    },
    InspectInvitation {
        invitation: Vec<u8>,
        checkpoint: Vec<u8>,
    },
    StageAdmissionUpdate {
        step: JoinStep,
    },
    AdoptAdmission {
        #[serde(default)]
        snapshot: Vec<u8>,
    },
    RetainedAdmission {
        authenticated_endpoint: [u8; 32],
        request: Vec<u8>,
    },
    IssueInvitation {},
    BeginJoin {
        invitation: Vec<u8>,
        #[serde(default)]
        checkpoint: Vec<u8>,
        display_name: String,
        #[serde(default)]
        peers: Vec<[u8; 32]>,
    },
    DriveJoin {},
    SealPendingJoin {},
    RestorePendingJoin {
        workspace: [u8; 32],
        #[serde(default)]
        snapshot: Vec<u8>,
    },
    CreateWorkspace {
        display_name: String,
        workspace_name: Option<String>,
    },
    SealWorkspace {},
    RestoreWorkspace {
        workspace: [u8; 32],
        #[serde(default)]
        snapshot: Vec<u8>,
    },
    AddAddressHint {
        peer: [u8; 32],
        address: String,
    },
    // Explicit all-member topic default; endpoints come from verified membership.
    InstallWorkspacePolicy {
        revision: u64,
    },
    InstallMemberPolicy {
        revision: u64,
        topics: Vec<String>,
    },
    // Development fixture only; rejected when the session owns a workspace.
    InstallVerifiedPolicy {
        workspace: [u8; 32],
        revision: u64,
        endpoints: Vec<EndpointPolicy>,
    },
    SetInterest {
        workspace: [u8; 32],
        revision: u64,
        topic: String,
        subscribed: bool,
    },
    PollInterest {},
    Subscribe {
        workspace: [u8; 32],
        revision: u64,
        topic: String,
    },
    Unsubscribe {
        workspace: [u8; 32],
        revision: u64,
        topic: String,
    },
    Publish {
        workspace: [u8; 32],
        revision: u64,
        topic: String,
        payload: Vec<u8>,
    },
    Poll {},
}

use membership::{JoinStep, WireManagement};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointPolicy {
    peer: [u8; 32],
    publish: Vec<String>,
    subscribe: Vec<String>,
}

fn report(value: AdmissionReport) -> Value {
    json!({ "admitted": value.admitted,
        "queued": value.queued,
        "failed": value.failed.into_iter().map(|(peer, error)|
            json!({"peer": peer, "error": error.to_string()})).collect::<Vec<_>>() })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationInspection {
    invitation: Vec<u8>,
    checkpoint: Vec<u8>,
}

/// Verify invitation presentation without allocating an endpoint or join identity.
pub fn inspect_invitation(request: &[u8]) -> Result<Vec<u8>, String> {
    if request.len() > MAX_REQUEST {
        return Err("request exceeds limit".into());
    }
    let request: InvitationInspection =
        serde_json::from_slice(request).map_err(|e| e.to_string())?;
    serde_json::to_vec(&inspected_invitation(
        &request.invitation,
        &request.checkpoint,
    )?)
    .map_err(|e| e.to_string())
}

fn invitation_envelope(
    session: &Session,
    invitation: &arachne_security::Invitation,
    checkpoint: Vec<u8>,
) -> Result<Value, String> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    let mut members = owner.member_endpoints().map_err(str::to_owned)?;
    members.sort_unstable();
    let bootstrap_peers = std::iter::once(session.node.id())
        .chain(
            members
                .iter()
                .copied()
                .filter(|peer| *peer != session.node.id()),
        )
        .take(3)
        .collect::<Vec<_>>();
    let mut routes = Vec::new();
    for peer in members {
        if peer != session.node.id()
            && let Some(address) = session.runtime.block_on(session.node.address_hint(peer))
            && address.is_ipv4()
            && !address.ip().is_unspecified()
        {
            routes.push(json!({"peer":peer,"address":address.to_string()}));
            if routes.len() == 7 {
                break;
            }
        }
    }
    Ok(
        json!({"workspace": owner.id(), "workspace_name":owner.workspace_name().map_err(str::to_owned)?, "invitation": invitation.export_secret_token().as_slice(), "invitation_key": invitation.key(), "checkpoint": checkpoint, "peer":session.node.id(), "bootstrap_peers":bootstrap_peers, "address":session.node.address().to_string(), "routes":routes}),
    )
}

fn inspected_invitation(invitation: &[u8], checkpoint: &[u8]) -> Result<Value, String> {
    let invitation = arachne_security::Invitation::from_bytes(invitation).map_err(str::to_owned)?;
    let proof = invitation.join_proof(checkpoint).map_err(str::to_owned)?;
    let control = proof
        .invitation_control(invitation.key())
        .map_err(str::to_owned)?;
    Ok(
        json!({"workspace":invitation.workspace_id(),"invitation_key":invitation.key(),"workspace_name":proof.workspace_name().map_err(str::to_owned)?,"epoch":proof.epoch(), "personal_invitation":control.as_ref().is_some_and(|c| c.personal), "automatic_approval":control.as_ref().is_some_and(|c| c.automatic()), "expires_at":control.map_or(0, |c| c.expires_at)}),
    )
}

fn member_metadata(workspace: &arachne_security::Workspace) -> Value {
    workspace.member().map_or(
        Value::Null,
        |member| json!({"id": member.id(), "display_name": member.display_name()}),
    )
}

fn pending_metadata(
    pending: &arachne_security::PendingJoin,
    endpoint: [u8; 32],
) -> Result<Value, String> {
    Ok(
        json!({"workspace": pending.workspace_id(), "workspace_name":pending.workspace_name().map_err(str::to_owned)?, "endpoint":endpoint, "state": "pending", "durable": false,
        "member": {"id": pending.member().id(), "display_name": pending.member().display_name()},
        "key_package": pending.key_package().map_err(str::to_owned)?,
        "personal_invitation":if pending.admission_request().is_ok() { pending.personal_invitation().map_err(str::to_owned)? } else { false }, "admission_request": pending.admission_request().ok()}),
    )
}

fn check_recovery_policy(
    session: &Session,
    peer: [u8; 32],
    author: [u8; 32],
    workspace: [u8; 32],
    epoch: u64,
    revision: u64,
    topics: &BTreeSet<Topic>,
) -> Result<(), String> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    if owner.id() != workspace || owner.epoch() != epoch {
        return Err("recovery scope changed".into());
    }
    if !owner
        .member_endpoints()
        .map_err(str::to_owned)?
        .contains(&peer)
    {
        return Err("recovery peer is not a current member".into());
    }
    let author_endpoint = owner
        .endpoints_for_members(&[author])
        .map_err(str::to_owned)?[0];
    session
        .runtime
        .block_on(session.node.with_routing_policy(|policy| {
            for topic in topics {
                let publishers = policy
                    .publishers(owner.id(), revision, session.node.id(), topic)
                    .map_err(|e| e.to_string())?;
                if !publishers.contains(&author_endpoint) {
                    return Err("recovery publisher is not authorized".to_owned());
                }
                if peer != author_endpoint
                    && !policy
                        .publishers(owner.id(), revision, peer, topic)
                        .map_err(|e| e.to_string())?
                        .contains(&author_endpoint)
                {
                    return Err("recovery holder is not authorized".to_owned());
                }
            }
            Ok(())
        }))
}

fn seal_state(
    native: bool,
    workspace: &arachne_security::Workspace,
    key: &arachne_security::StorageKey,
    publisher: Option<&arachne_delivery::PublisherLog>,
    received: Option<&arachne_delivery::receive::ReceiveJournal>,
    inbox: Option<&arachne_delivery::inbox::ObjectInbox>,
) -> Result<Vec<u8>, String> {
    if native {
        return persistence::candidate_token();
    }
    if let Some(inbox) = inbox {
        return inbox
            .with_legacy_receipts(received)
            .seal(
                workspace,
                key,
                publisher.ok_or("object inbox requires publisher state")?,
            )
            .map_err(str::to_owned);
    }
    match (publisher, received) {
        (Some(log), Some(received)) => log.seal_with_receipts(workspace, key, received),
        (Some(log), None) => log.seal(workspace, key),
        (None, None) => workspace.seal(key),
        (None, Some(_)) => return Err("receive journal requires publisher state".into()),
    }
    .map_err(str::to_owned)
}

// Epoch changes cannot silently discard accepted pending application work.
fn check_epoch_transition(session: &mut Session) -> Result<(), String> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    if let Some(inbox) = &session.inbox {
        // Keep owner/authentication checks, but count work hidden behind direct gaps too.
        inbox.pending(owner).map_err(str::to_owned)?;
        if inbox.pending_count() > 0 {
            return Err(
                "pending application delivery must be acknowledged before membership update".into(),
            );
        }
    }
    if !session.recovered.is_empty() {
        return Err("recovery must finish or cancel before membership update".into());
    }
    // Background discovery/download has accepted no application work. A new
    // epoch invalidates its query anyway; cancel it instead of making normal
    // membership actions race the periodic history poller. Accepted inbox and
    // recovered deliveries above must still drain before this point.
    drop(session.cutoff.take());
    drop(session.range.take());
    session.ready_range = None;
    drop(session.direct_range.take());
    session.ready_direct_range = None;
    session.direct_miss = None;
    drop(session.current_view.take());
    session.ready_current_view = None;
    Ok(())
}

fn stage_admission(
    session: &mut Session,
    authenticated_endpoint: [u8; 32],
    request: &[u8],
    checkpoint: Option<&[u8]>,
    validated: Option<&arachne_security::ValidatedAdmission>,
) -> Result<Value, String> {
    check_epoch_transition(session)?;
    let workspace = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    if workspace
        .retained_admission(authenticated_endpoint, request)
        .map_err(str::to_owned)?
        .is_some()
    {
        return Err("admission already retained; retrieve its existing response".into());
    }
    let prepared = match validated {
        Some(validated) => workspace
            .prepare_validated_admission(authenticated_endpoint, request, validated)
            .map_err(str::to_owned)?,
        None => workspace
            .prepare_admission(authenticated_endpoint, request)
            .map_err(str::to_owned)?,
    };
    // Reject missing/oversized reply history while the accepted owner is unchanged.
    if checkpoint.is_some() {
        admission_reply(
            &prepared.workspace,
            authenticated_endpoint,
            request,
            checkpoint,
        )?;
    }
    stage_admission_workspace(session, prepared.workspace, 1)
}

fn stage_admission_workspace(
    session: &mut Session,
    workspace: arachne_security::Workspace,
    admission_count: usize,
) -> Result<Value, String> {
    let key = session
        .storage_key
        .as_ref()
        .ok_or("session has no protected root key")?;
    let snapshot = seal_state(session.records.is_some(), &workspace, key, None, None, None)?;
    let value = json!({"workspace": workspace.id(), "snapshot": snapshot, "state":"awaiting_save", "durable":false,
        "admissions": admission_count});
    session.staged_workspace = Some(StagedWorkspace {
        received: None,
        inbox: None,
        publisher: None, // New epoch; this prototype retains current-epoch history only.
        transition: WorkspaceTransition::Admission,
        workspace,
        snapshot,
    });
    Ok(value)
}

fn retained_reply(
    workspace: &arachne_security::Workspace,
    authenticated_endpoint: [u8; 32],
    request: &[u8],
) -> Result<Value, String> {
    let reply = workspace
        .retained_admission(authenticated_endpoint, request)
        .map_err(str::to_owned)?
        .ok_or("no retained admission")?;
    Ok(
        json!({"workspace":workspace.id(), "epoch":reply.epoch, "commit":reply.commit, "welcome":reply.welcome,
            "authorization":{"invitation_key":reply.authorization.invitation_key,
                "grant_signature":reply.authorization.grant_signature.as_slice(),
                "redemption_signature":reply.authorization.redemption_signature.as_slice()}}),
    )
}

// Versioned admission transport wrapper. Legacy local/raw requests remain
// available; the plugin sends its pinned checkpoint for history preflight.
type AdmissionPacket<'a> = (&'a [u8], Option<&'a [u8]>, Option<&'a str>);

const ADMISSION_HISTORY_PAGE_REQUEST: &[u8; 5] = b"DFJP\x01";

fn admission_packet(bytes: &[u8]) -> Result<AdmissionPacket<'_>, String> {
    if !bytes.starts_with(b"DFJA") {
        return Ok((bytes, None, None));
    }
    if bytes.len() < 9 || (!bytes.starts_with(b"DFJA\x01") && !bytes.starts_with(b"DFJA\x02")) {
        return Err("invalid admission packet".into());
    }
    let length = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
    let (header, name_length): (usize, usize) = if bytes.starts_with(b"DFJA\x02") {
        if bytes.len() < 11 {
            return Err("invalid admission packet bounds".into());
        }
        (
            11,
            u16::from_be_bytes(bytes[9..11].try_into().unwrap()) as usize,
        )
    } else {
        (9, 0)
    };
    let request_end = header
        .checked_add(length)
        .ok_or("invalid admission packet bounds")?;
    let name_end = request_end
        .checked_add(name_length)
        .ok_or("invalid admission packet bounds")?;
    if length == 0 || name_end >= bytes.len() {
        return Err("invalid admission packet bounds".into());
    }
    let name = if name_length == 0 {
        None
    } else {
        let value = std::str::from_utf8(&bytes[request_end..name_end])
            .map_err(|_| "invalid admission display name")?;
        if value.trim() != value
            || value.is_empty()
            || value.len() > 256
            || value.chars().count() > 80
            || value.chars().any(|c| {
                c.is_control()
                    || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            })
        {
            return Err("invalid admission display name".into());
        }
        Some(value)
    };
    Ok((&bytes[header..request_end], Some(&bytes[name_end..]), name))
}

fn admission_parts(bytes: &[u8]) -> Result<(&[u8], Option<&[u8]>), String> {
    let (request, checkpoint, _) = admission_packet(bytes)?;
    Ok((request, checkpoint))
}

fn admission_history_page_packet(
    request: &[u8],
    checkpoint: &[u8],
    offset: usize,
) -> Result<Vec<u8>, String> {
    let request_len = u32::try_from(request.len()).map_err(|_| "admission request too large")?;
    let checkpoint_len = u32::try_from(checkpoint.len()).map_err(|_| "checkpoint too large")?;
    let offset = u32::try_from(offset).map_err(|_| "history offset too large")?;
    let mut packet = ADMISSION_HISTORY_PAGE_REQUEST.to_vec();
    packet.extend(request_len.to_be_bytes());
    packet.extend(checkpoint_len.to_be_bytes());
    packet.extend(offset.to_be_bytes());
    packet.extend(request);
    packet.extend(checkpoint);
    Ok(packet)
}

fn join_attempt_error(error: arachne_node::Error, initial: bool) -> JoinAttemptOutcome {
    match error {
        arachne_node::Error::ControlNotSent(_) | arachne_node::Error::MissingPeer if initial => {
            JoinAttemptOutcome::NotSent
        }
        arachne_node::Error::ControlNotSent(_)
        | arachne_node::Error::MissingPeer
        | arachne_node::Error::Timeout(_)
        | arachne_node::Error::Transport(_) => JoinAttemptOutcome::Waiting,
        error => JoinAttemptOutcome::Failed(error.to_string()),
    }
}

async fn request_invitation_checkpoint(
    client: ControlClient,
    requester: [u8; 32],
    invitation: Vec<u8>,
    peers: Vec<[u8; 32]>,
) -> Result<Value, String> {
    let invitation =
        arachne_security::Invitation::from_bytes(&invitation).map_err(str::to_owned)?;
    if peers.is_empty()
        || peers.len() > 3
        || peers.iter().any(|peer| peer == &requester)
        || peers
            .iter()
            .enumerate()
            .any(|(index, peer)| peers[..index].contains(peer))
    {
        return Err("checkpoint discovery requires one to three distinct peers".into());
    }
    let mut last_error = None;
    for peer in peers {
        let mut packet = INVITATION_CHECKPOINT_REQUEST.to_vec();
        packet.extend(
            invitation
                .checkpoint_request(requester, peer)
                .map_err(str::to_owned)?,
        );
        let checkpoint = match client.clone().request_control(peer, &packet).await {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                last_error = Some(error.to_string());
                continue;
            }
        };
        match invitation.join_proof(&checkpoint) {
            Ok(_) => {
                return Ok(json!({
                    "workspace": invitation.workspace_id(),
                    "checkpoint": checkpoint,
                    "peer": peer,
                }));
            }
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    Err(last_error.unwrap_or_else(|| "no authorized workspace member is reachable".into()))
}

async fn request_join_exchange(
    client: ControlClient,
    peer: [u8; 32],
    request: Vec<u8>,
    name: Vec<u8>,
    checkpoint: Vec<u8>,
) -> JoinAttemptOutcome {
    let mut packet = b"DFJA\x02".to_vec();
    let request_len = match u32::try_from(request.len()) {
        Ok(length) => length,
        Err(_) => return JoinAttemptOutcome::Failed("admission request too large".into()),
    };
    let name_len = match u16::try_from(name.len()) {
        Ok(length) => length,
        Err(_) => return JoinAttemptOutcome::Failed("admission display name too large".into()),
    };
    packet.extend(request_len.to_be_bytes());
    packet.extend(name_len.to_be_bytes());
    packet.extend(&request);
    packet.extend(&name);
    packet.extend(&checkpoint);

    let first = match client.clone().request_control(peer, &packet).await {
        Ok(reply) => reply,
        Err(error) => return join_attempt_error(error, true),
    };
    let mut page_bytes = vec![first.len()];
    let mut reply: Value = match serde_json::from_slice(&first) {
        Ok(value) => value,
        Err(_) => return JoinAttemptOutcome::Failed("invalid admission reply".into()),
    };
    if reply
        .get("history_complete")
        .is_some_and(|complete| !complete.as_bool().unwrap_or(false))
    {
        let mut commits = match reply["commits"].as_array().cloned() {
            Some(commits) => commits,
            None => {
                return JoinAttemptOutcome::Failed("admission history page missing commits".into());
            }
        };
        let mut offset = match reply["history_next"].as_u64() {
            Some(offset) => offset as usize,
            None => {
                return JoinAttemptOutcome::Failed(
                    "admission history page missing next offset".into(),
                );
            }
        };
        let mut page_count = 0;
        let mut total_bytes = first.len();
        while !reply["history_complete"].as_bool().unwrap_or(false) {
            page_count += 1;
            if page_count > arachne_security::MAX_JOIN_HISTORY_STEPS {
                return JoinAttemptOutcome::Failed(
                    "admission history page count exceeds bounds".into(),
                );
            }
            let page = match admission_history_page_packet(&request, &checkpoint, offset) {
                Ok(packet) => packet,
                Err(error) => return JoinAttemptOutcome::Failed(error),
            };
            let page = match client.clone().request_control(peer, &page).await {
                Ok(page) => page,
                Err(error) => return join_attempt_error(error, false),
            };
            total_bytes = total_bytes.saturating_add(page.len());
            if total_bytes > arachne_security::MAX_JOIN_HISTORY_BYTES {
                return JoinAttemptOutcome::Failed(
                    "admission history exceeds transport bounds".into(),
                );
            }
            page_bytes.push(page.len());
            let page: Value = match serde_json::from_slice(&page) {
                Ok(value) => value,
                Err(_) => {
                    return JoinAttemptOutcome::Failed("invalid admission history page".into());
                }
            };
            if page.get("history_page").and_then(Value::as_bool) != Some(true) {
                return JoinAttemptOutcome::Failed(
                    "admission history page was not accepted".into(),
                );
            }
            if page["history_offset"].as_u64() != Some(offset as u64) {
                return JoinAttemptOutcome::Failed("admission history page offset mismatch".into());
            }
            let page_commits = match page["commits"].as_array() {
                Some(commits) => commits,
                None => {
                    return JoinAttemptOutcome::Failed(
                        "admission history page missing commits".into(),
                    );
                }
            };
            let next = match page["history_next"].as_u64() {
                Some(next) => next as usize,
                None => {
                    return JoinAttemptOutcome::Failed(
                        "admission history page missing next offset".into(),
                    );
                }
            };
            if page_commits.is_empty() || next <= offset {
                return JoinAttemptOutcome::Failed(
                    "admission history page made no progress".into(),
                );
            }
            if commits.len() + page_commits.len() > arachne_security::MAX_JOIN_HISTORY_STEPS {
                return JoinAttemptOutcome::Failed("admission history exceeds step bounds".into());
            }
            commits.extend(page_commits.iter().cloned());
            offset = next;
            reply = page;
        }
        reply["commits"] = Value::Array(commits);
        reply["history_complete"] = Value::Bool(true);
    }

    let mut history_prefix = Vec::new();
    let total = reply["commits"].as_array().map_or(0, Vec::len);
    if total > arachne_security::HISTORY_CHUNK_STEPS {
        let trailing = match total % arachne_security::HISTORY_CHUNK_STEPS {
            0 => arachne_security::HISTORY_CHUNK_STEPS,
            remainder => remainder,
        };
        let split = total - trailing;
        let commits = reply["commits"].as_array().unwrap();
        history_prefix = commits[..split].to_vec();
        reply["commits"] = Value::Array(commits[split..].to_vec());
        reply["history_verified_prefix"] = json!(split);
    }
    if reply.get("commits").is_some() {
        reply["history_page_bytes"] = json!(page_bytes);
    }
    JoinAttemptOutcome::Reply {
        value: reply,
        history_prefix,
    }
}

fn parse_admission_history_page_packet(bytes: &[u8]) -> Result<(&[u8], &[u8], usize), String> {
    if !bytes.starts_with(ADMISSION_HISTORY_PAGE_REQUEST) || bytes.len() < 17 {
        return Err("invalid admission history page request".into());
    }
    let request_len = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
    let checkpoint_len = u32::from_be_bytes(bytes[9..13].try_into().unwrap()) as usize;
    let offset = u32::from_be_bytes(bytes[13..17].try_into().unwrap()) as usize;
    let request_end = 17usize
        .checked_add(request_len)
        .ok_or("invalid admission history page bounds")?;
    let checkpoint_end = request_end
        .checked_add(checkpoint_len)
        .ok_or("invalid admission history page bounds")?;
    if request_len == 0 || checkpoint_end != bytes.len() {
        return Err("invalid admission history page bounds".into());
    }
    Ok((
        &bytes[17..request_end],
        &bytes[request_end..checkpoint_end],
        offset,
    ))
}

const INVITATION_CHECKPOINT_REQUEST: &[u8; 5] = b"DFIC\x01";

fn invitation_checkpoint_reply(
    session: &Session,
    requester: [u8; 32],
    request: &[u8],
) -> Result<Vec<u8>, String> {
    let proof = request
        .strip_prefix(INVITATION_CHECKPOINT_REQUEST)
        .ok_or("invalid invitation checkpoint request")?;
    let workspace = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    workspace
        .checkpoint_for_invitation(requester, session.node.id(), proof)
        .map_err(str::to_owned)
}

#[test]
fn admission_packet_rejects_invalid_version_and_lengths() {
    let packet = [b"DFJA\x01".as_slice(), &1u32.to_be_bytes(), &[7, 8]].concat();
    assert_eq!(
        admission_parts(&packet).unwrap(),
        (&[7][..], Some(&[8][..]))
    );
    let named = [
        b"DFJA\x02".as_slice(),
        &1u32.to_be_bytes(),
        &4u16.to_be_bytes(),
        &[7],
        b"Alex",
        &[8],
    ]
    .concat();
    assert_eq!(
        admission_packet(&named).unwrap(),
        (&[7][..], Some(&[8][..]), Some("Alex"))
    );
    for length in 4..packet.len() {
        assert!(admission_parts(&packet[..length]).is_err());
    }
    for length in [0, 2, u32::MAX] {
        let mut bad = packet.clone();
        bad[5..9].copy_from_slice(&length.to_be_bytes());
        assert!(admission_parts(&bad).is_err());
    }
    let mut bad = packet;
    bad[4] = 2;
    assert!(admission_parts(&bad).is_err());
}

fn admission_reply(
    workspace: &arachne_security::Workspace,
    peer: [u8; 32],
    request: &[u8],
    checkpoint: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    admission_reply_page(workspace, peer, request, checkpoint, 0)
}

fn send_inbound_admission_reply(session: &mut Session) -> Result<Value, String> {
    let incoming = session
        .inbound_admission
        .take()
        .ok_or("session has no received admission")?;
    let workspace = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    let reply = if incoming.payload().starts_with(b"DFLV") {
        membership::leave_reply(workspace, incoming.peer(), incoming.payload())?
    } else if incoming.payload().starts_with(b"DFMO")
        || incoming.payload().starts_with(ADMISSION_RESULT_OFFER)
    {
        vec![1] // Acknowledge only after the staged transition or verified Welcome is durable.
    } else {
        let (request, checkpoint) = admission_parts(incoming.payload())?;
        admission_reply(workspace, incoming.peer(), request, checkpoint)?
    };
    let queued = match incoming.respond(reply) {
        Ok(()) => true,
        Err(arachne_node::Error::Rejected) => false, // Requester expired; saved admission remains retryable.
        Err(error) => return Err(error.to_string()),
    };
    Ok(json!({"queued":queued,"remote_receipt":false}))
}

fn admission_reply_page(
    workspace: &arachne_security::Workspace,
    peer: [u8; 32],
    request: &[u8],
    checkpoint: Option<&[u8]>,
    offset: usize,
) -> Result<Vec<u8>, String> {
    let mut reply = retained_reply(workspace, peer, request)?;
    if let Some(checkpoint) = checkpoint {
        let mut steps = workspace
            .membership_history(peer, request, checkpoint)
            .map_err(str::to_owned)?;
        let last = steps
            .iter()
            .position(|(_, commit)| json!(commit) == reply["commit"])
            .ok_or("retained admission missing from verified history")?;
        steps.truncate(last + 1); // Retry may follow later Adds; Welcome pins this exact step.
        if offset >= steps.len() {
            return Err("admission history page offset is out of bounds".into());
        }
        let mut page = Vec::new();
        let mut next = offset;
        for (authorization, commit) in steps.iter().skip(offset) {
            let step = membership::step_json(authorization, commit);
            let mut candidate = page.clone();
            candidate.push(step);
            reply["commits"] = json!(candidate);
            reply["history_offset"] = json!(offset);
            reply["history_next"] = json!(next + 1);
            reply["history_complete"] = json!(next + 1 == steps.len());
            if serde_json::to_vec(&reply).map_err(|e| e.to_string())?.len()
                > arachne_node::MAX_CONTROL_REPLY
            {
                if page.is_empty() {
                    return Err("admission history step exceeds transport bound".into());
                }
                break;
            }
            page = candidate;
            next += 1;
        }
        reply["commits"] = json!(page);
        if next < steps.len() || offset > 0 {
            reply["history_offset"] = json!(offset);
            reply["history_next"] = json!(next);
            reply["history_complete"] = json!(next == steps.len());
            reply["history_page"] = json!(true);
        } else if let Some(object) = reply.as_object_mut() {
            object.remove("history_offset");
            object.remove("history_next");
            object.remove("history_complete");
            object.remove("history_page");
        }
    }
    let encoded = serde_json::to_vec(&reply).map_err(|e| e.to_string())?;
    if encoded.len() > arachne_node::MAX_CONTROL_REPLY {
        return Err("admission reply exceeds transport bound".into());
    }
    Ok(encoded)
}

fn admission_packet_candidate(bytes: &[u8]) -> bool {
    bytes.starts_with(b"DFJA")
        || bytes.starts_with(b"DFJR\x01")
        || bytes.starts_with(ADMISSION_HISTORY_PAGE_REQUEST)
}

fn admission_offer_candidate(bytes: &[u8]) -> bool {
    bytes.starts_with(ADMISSION_RESULT_OFFER)
}

fn admission_offer_packet(reply: &[u8]) -> Result<Vec<u8>, String> {
    let length = u32::try_from(reply.len()).map_err(|_| "admission result is too large")?;
    if reply.len() > 32 * 1024 - 9 {
        return Err("admission result offer exceeds control bound".into());
    }
    let mut packet = ADMISSION_RESULT_OFFER.to_vec();
    packet.extend(length.to_be_bytes());
    packet.extend(reply);
    Ok(packet)
}

fn parse_admission_offer(packet: &[u8]) -> Result<(Vec<JoinStep>, Vec<u8>), String> {
    if packet.len() < 9 || !packet.starts_with(ADMISSION_RESULT_OFFER) {
        return Err("invalid admission result offer".into());
    }
    let length = u32::from_be_bytes(packet[5..9].try_into().unwrap()) as usize;
    if length == 0 || packet.len() != 9 + length || packet.len() > 32 * 1024 {
        return Err("invalid admission result offer bounds".into());
    }
    let reply: Value = serde_json::from_slice(&packet[9..]).map_err(|_| "invalid admission result")?;
    if reply.get("history_complete").and_then(Value::as_bool) == Some(false) {
        return Err("paged admission result requires the retry path".into());
    }
    let commits = if let Some(commits) = reply.get("commits") {
        serde_json::from_value(commits.clone()).map_err(|_| "invalid admission result commits")?
    } else {
        vec![serde_json::from_value(json!({
            "commit": reply["commit"].clone(),
            "authorization": reply["authorization"].clone(),
        }))
        .map_err(|_| "incomplete admission result")?]
    };
    if commits.is_empty() || commits.len() > arachne_security::HISTORY_CHUNK_STEPS {
        return Err("admission result history exceeds bounds".into());
    }
    let welcome = serde_json::from_value(reply["welcome"].clone())
        .map_err(|_| "admission result has no Welcome")?;
    Ok((commits, welcome))
}

fn reap_admission_pushes(session: &mut Session) {
    session
        .admission_pushes
        .retain(|push| !push.task.is_finished());
}

fn queue_admission_push(
    session: &mut Session,
    attempt: &arachne_security::AdmissionAttempt,
    reply: &[u8],
    route: Option<std::net::SocketAddr>,
) -> bool {
    if serde_json::from_slice::<Value>(reply)
        .ok()
        .and_then(|value| value.get("history_complete").and_then(Value::as_bool))
        == Some(false)
    {
        return false;
    }
    let Ok(packet) = admission_offer_packet(reply) else {
        return false;
    };
    let peer = attempt.endpoint();
    if let Some(route) = route {
        let _ = session
            .runtime
            .block_on(session.node.add_address_hint(peer, route));
    }
    // The request itself arrived over an authenticated control path, so Iroh
    // already has a route or relay identity for this peer. Refreshing an IP
    // hint is optional; one bounded request is the push attempt, and the
    // retained reply remains the recovery path if it fails.
    let client = session.node.control_client();
    let wake = session.node.control_signal();
    let task = session.runtime.spawn(async move {
        let result = client.request_control(peer, &packet).await;
        wake.notify_one();
        result
    });
    session.admission_pushes.push(PendingControl {
        query: attempt.id(),
        peer,
        task,
    });
    true
}

fn admission_reason(error: &str) -> &'static str {
    match error {
        arachne_security::INVITATION_AUTOMATIC_APPROVAL_REQUIRED => "automatic_approval_required",
        arachne_security::INVITATION_APPROVAL_REQUIRED => "approval_required",
        arachne_security::INVITATION_DISABLED => "invitation_disabled",
        arachne_security::INVITATION_EXPIRED => "invitation_expired",
        "member already admitted" => admission_state::MEMBER_ALREADY_ADMITTED,
        _ => "unavailable",
    }
}

fn admission_feedback(error: &str) -> Value {
    let reason = admission_reason(error);
    if reason == admission_state::MEMBER_ALREADY_ADMITTED {
        json!({
            "state": admission_state::RECOVERY_REQUIRED,
            "reason": reason,
            "recovery": admission_state::RECOVERY_REMOVE_AND_REINVITE,
        })
    } else {
        json!({"state": admission_state::UNAVAILABLE, "reason": reason})
    }
}

fn enqueue_admission(
    session: &mut Session,
    attempt: arachne_security::AdmissionAttempt,
    checkpoint: Option<Vec<u8>>,
    display_name: Option<String>,
    approval_automatic: Option<bool>,
    validated: arachne_security::ValidatedAdmission,
) -> Result<arachne_security::AdmissionEnqueue, arachne_security::AdmissionQueueError> {
    let id = attempt.id();
    let result = session.admission_queue.enqueue(attempt)?;
    if result == arachne_security::AdmissionEnqueue::Added {
        session.admission_metadata.insert(
            id,
            QueuedAdmission {
                checkpoint,
                display_name,
                approval_automatic,
                validated,
            },
        );
    }
    Ok(result)
}

/// Keep the requester's exchange open for its result. Past the bound, answer
/// `admission_queued`; that requester retries and finds the retained result.
fn hold_admission_exchange(
    session: &mut Session,
    attempt: [u8; 32],
    incoming: arachne_node::ControlRequest,
    checkpoint: Option<Vec<u8>>,
) {
    if let Some(overflow) = session
        .admission_waiters
        .hold(attempt, incoming, checkpoint)
    {
        let _ = overflow.respond(b"{\"state\":\"admission_queued\"}".to_vec());
    }
}

fn queue_admission(
    session: &mut Session,
    incoming: arachne_node::ControlRequest,
) -> Result<Value, String> {
    session.admission_reads_since_stage = session.admission_reads_since_stage.saturating_add(1);
    let peer = incoming.peer();
    let packet = incoming.payload().to_vec();
    if packet.starts_with(ADMISSION_HISTORY_PAGE_REQUEST) {
        let response = match parse_admission_history_page_packet(&packet) {
            Ok((request, checkpoint, offset)) => session.workspace.as_ref().map_or_else(
                || b"{\"state\":\"admission_unavailable\",\"reason\":\"unavailable\"}".to_vec(),
                |workspace| {
                    admission_reply_page(workspace, peer, request, Some(checkpoint), offset)
                        .unwrap_or_else(|_| {
                            b"{\"state\":\"admission_unavailable\",\"reason\":\"unavailable\"}"
                                .to_vec()
                        })
                },
            ),
            Err(_) => b"{\"state\":\"admission_unavailable\",\"reason\":\"unavailable\"}".to_vec(),
        };
        let accepted = incoming.respond(response).is_ok();
        return Ok(json!({"state":"admission_replied", "accepted":accepted,
            "history_page":true}));
    }
    let (request, checkpoint, display_name) = match admission_packet(&packet) {
        Ok((request, checkpoint, display_name)) => (
            request.to_vec(),
            checkpoint.map(ToOwned::to_owned),
            display_name.map(str::to_owned),
        ),
        Err(_) => {
            let _ = incoming.respond(
                serde_json::to_vec(
                    &json!({"state":"admission_unavailable","reason":"unavailable"}),
                )
                .map_err(|_| "admission feedback encoding failed")?,
            );
            return Ok(json!({"state":"admission_replied","accepted":false}));
        }
    };
    let attempt =
        arachne_security::AdmissionAttempt::new(peer, request.clone()).map_err(str::to_owned)?;
    {
        let workspace = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        if workspace
            .retained_admission(peer, &request)
            .map_err(str::to_owned)?
            .is_some()
        {
            let reply = admission_reply_page(workspace, peer, &request, checkpoint.as_deref(), 0)?;
            let accepted = incoming.respond(reply).is_ok();
            if accepted {
                session
                    .queued_admission_in_flight
                    .retain(|queued| queued != &attempt);
            }
            return Ok(json!({"state":"admission_replied", "accepted":accepted}));
        }
    }
    if session.admission_queue.contains(&attempt)
        || session
            .queued_admission_in_flight
            .iter()
            .any(|queued| queued == &attempt)
    {
        hold_admission_exchange(session, attempt.id(), incoming, checkpoint);
        return Ok(json!({"state":"admission_queued"}));
    }

    let assessment = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?
        .assess_admission(peer, &request);
    if session.pending_approvals.contains_key(&attempt.id()) {
        let still_needs_approval = matches!(
            &assessment,
            Ok(arachne_security::AdmissionAssessment::ApprovalRequired(_))
                | Ok(arachne_security::AdmissionAssessment::AutomaticApprovalRequired(_))
        );
        if still_needs_approval {
            let _ = incoming.respond(b"{\"state\":\"admission_queued\"}".to_vec());
            return Ok(json!({"state":"admission_queued"}));
        }
        // A workspace transition applied elsewhere may have approved or
        // declined this request. The next retry must observe that state.
        session.pending_approvals.remove(&attempt.id());
    }
    let (validated, approval_automatic) = match assessment {
        Ok(arachne_security::AdmissionAssessment::Ready(request)) => (request, None),
        Ok(arachne_security::AdmissionAssessment::ApprovalRequired(request)) => {
            (request, Some(false))
        }
        Ok(arachne_security::AdmissionAssessment::AutomaticApprovalRequired(request)) => {
            (request, Some(true))
        }
        Err(error) => {
            let feedback = admission_feedback(error);
            let _ = incoming.respond(
                serde_json::to_vec(&feedback)
                    .map_err(|_| "admission feedback encoding failed")?,
            );
            let mut result = json!({"state":admission_state::REPLIED,"accepted":false});
            for key in ["reason", "recovery"] {
                if let Some(value) = feedback.get(key) {
                    result[key] = value.clone();
                }
            }
            if let Some(name) = display_name {
                result["display_name"] = json!(name);
            }
            return Ok(result);
        }
    };

    if approval_automatic.is_some() {
        if enqueue_admission(
            session,
            attempt,
            checkpoint,
            display_name,
            approval_automatic,
            validated,
        )
        .is_err()
        {
            let _ = incoming.respond(
                b"{\"state\":\"admission_unavailable\",\"reason\":\"server_busy\"}".to_vec(),
            );
            return Ok(json!({"state":"admission_replied","accepted":false}));
        }
        let _ = incoming.respond(b"{\"state\":\"admission_queued\"}".to_vec());
        return Ok(json!({"state":"admission_queued"}));
    }

    if let Some(checkpoint) = checkpoint.as_deref()
        && session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?
            // Intake only needs to know the pinned history is servable. The
            // transitions themselves are built once, on the reply path, rather
            // than materialized and discarded for every arriving request.
            .check_membership_history(peer, &request, checkpoint)
            .is_err()
    {
        let _ = incoming.respond(
            serde_json::to_vec(&json!({"state":"admission_unavailable","reason":"unavailable"}))
                .map_err(|_| "admission feedback encoding failed")?,
        );
        return Ok(json!({"state":"admission_replied","accepted":false}));
    }
    let attempt_id = attempt.id();
    let held_checkpoint = checkpoint.clone();
    if enqueue_admission(session, attempt, checkpoint, display_name, None, validated).is_err() {
        let _ = incoming
            .respond(b"{\"state\":\"admission_unavailable\",\"reason\":\"server_busy\"}".to_vec());
        return Ok(json!({"state":"admission_replied","accepted":false}));
    }
    hold_admission_exchange(session, attempt_id, incoming, held_checkpoint);
    // Distinguishes a newly accepted request -- the one that paid for
    // checkpoint preflight -- from a retry of one already queued, which
    // short-circuits far earlier. The wire reply is unchanged.
    Ok(json!({"state":"admission_queued","intake":true}))
}

/// Whether this poll should stage before it reads another admission packet.
/// The normal trigger is elsewhere: PollAdmission stages when no admission
/// packet is waiting. This is the forced-progress trigger for a busy inbox: a
/// full batch, or a full batch's worth of reads since the last attempt. Both
/// are counts. Nothing on this path waits for time to pass.
fn should_stage_queued_admission(session: &Session) -> bool {
    !session.admission_queue.is_empty()
        && (session.admission_queue.len() >= MAX_RUNTIME_ADMISSION_BATCH
            || session.admission_reads_since_stage >= MAX_RUNTIME_ADMISSION_BATCH)
}

fn stage_queued_admission(session: &mut Session) -> Result<Option<Value>, String> {
    session.admission_reads_since_stage = 0;
    let mut ready = Vec::new();
    let mut deferred = Vec::new();
    while ready.len() < MAX_RUNTIME_ADMISSION_BATCH {
        let Some(attempt) = session.admission_queue.pop() else {
            break;
        };
        let Some(queued) = session.admission_metadata.remove(&attempt.id()) else {
            continue;
        };
        if queued.approval_automatic.is_some() {
            deferred.push((attempt, queued));
            continue;
        }
        // A retry may have completed this request while it was queued. Do not
        // block later joiners on a stale duplicate.
        if session
            .workspace
            .as_ref()
            .and_then(|workspace| {
                workspace
                    .retained_admission(attempt.endpoint(), attempt.request())
                    .ok()
                    .flatten()
            })
            .is_some()
        {
            continue;
        }
        ready.push((attempt, queued));
    }

    if ready.is_empty() {
        let mut deferred = deferred.into_iter();
        let Some((attempt, queued)) = deferred.next() else {
            return Ok(None);
        };
        for (attempt, queued) in deferred {
            requeue_admission(session, attempt, queued)?;
        }
        let id = attempt.id();
        let pending = session
            .pending_approvals
            .entry(id)
            .or_insert(PendingAdmissionApproval {
                attempt,
                queued,
                delivered: false,
                acknowledged: false,
            });
        pending.delivered = true;
        return Ok(Some(
            json!({"state":admission_state::APPROVAL_REQUESTED,"attempt_id":id,
            "endpoint":pending.attempt.endpoint(),"request":pending.attempt.request(),
            "display_name":pending.queued.display_name,
            "automatic":pending.queued.approval_automatic.unwrap_or(false)}),
        ));
    }

    if let Err(error) = check_epoch_transition(session) {
        for (attempt, queued) in deferred {
            requeue_admission(session, attempt, queued)?;
        }
        for (attempt, queued) in ready {
            requeue_admission(session, attempt, queued)?;
        }
        return Err(error);
    }

    for (attempt, queued) in deferred {
        requeue_admission(session, attempt, queued)?;
    }
    let inputs: Vec<_> = ready
        .iter()
        .map(|(attempt, queued)| (attempt.endpoint(), attempt.request(), &queued.validated))
        .collect();
    let prepared = match session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?
        .prepare_validated_admission_batch(&inputs)
    {
        Ok(prepared) => prepared,
        Err(error) => {
            for (attempt, queued) in ready {
                requeue_admission(session, attempt, queued)?;
            }
            return Err(error.to_owned());
        }
    };
    let history_check = ready.iter().try_for_each(|(attempt, queued)| {
        queued.checkpoint.as_deref().map_or(Ok(()), |checkpoint| {
            admission_reply(
                &prepared.workspace,
                attempt.endpoint(),
                attempt.request(),
                Some(checkpoint),
            )
            .map(|_| ())
        })
    });
    if let Err(error) = history_check {
        for (attempt, queued) in ready {
            requeue_admission(session, attempt, queued)?;
        }
        return Err(error);
    }
    let count = ready.len();
    let mut value = match stage_admission_workspace(session, prepared.workspace, count) {
        Ok(value) => value,
        Err(error) => {
            for (attempt, queued) in ready {
                requeue_admission(session, attempt, queued)?;
            }
            return Err(error);
        }
    };
    let attempts = ready.into_iter().map(|(attempt, _)| attempt).collect();
    session.queued_admission_in_flight = attempts;
    value["queued"] = json!(true);
    Ok(Some(value))
}

fn requeue_admission(
    session: &mut Session,
    attempt: arachne_security::AdmissionAttempt,
    queued: QueuedAdmission,
) -> Result<(), String> {
    let id = attempt.id();
    session
        .admission_queue
        .enqueue(attempt)
        .map_err(|_| "admission queue is full".to_owned())?;
    session.admission_metadata.insert(id, queued);
    Ok(())
}

fn pending_approval_id(
    session: &Session,
    request: &[u8],
    requested: Option<[u8; 32]>,
) -> Result<Option<[u8; 32]>, String> {
    if let Some(id) = requested {
        let pending = session
            .pending_approvals
            .get(&id)
            .ok_or("admission approval is no longer pending")?;
        if pending.attempt.request() != request {
            return Err("admission approval request does not match attempt".into());
        }
        return Ok(Some(id));
    }
    Ok(session
        .pending_approvals
        .iter()
        .find(|(_, pending)| pending.attempt.request() == request)
        .map(|(id, _)| *id))
}

fn list_pending_approvals(
    session: &Session,
    after: Option<[u8; 32]>,
    limit: Option<usize>,
) -> Result<Value, String> {
    let limit = limit.unwrap_or(64);
    if !(1..=64).contains(&limit) {
        return Err("approval page limit must be between 1 and 64".into());
    }
    let rows: Vec<_> = session
        .pending_approvals
        .iter()
        .filter(|(id, _)| after.is_none_or(|after| **id > after))
        .take(limit + 1)
        .collect();
    let complete = rows.len() <= limit;
    let rows = rows.into_iter().take(limit).map(|(id, pending)| {
        json!({
            "attempt_id": id,
            "endpoint": pending.attempt.endpoint(),
            "request": pending.attempt.request(),
            "display_name": pending.queued.display_name,
            "automatic": pending.queued.approval_automatic.unwrap_or(false),
            "delivered": pending.delivered,
            "acknowledged": pending.acknowledged,
        })
    });
    let approvals: Vec<_> = rows.collect();
    let next_after = approvals
        .last()
        .and_then(|value| value["attempt_id"].as_array())
        .and_then(|bytes| bytes.iter().map(Value::as_u64).collect::<Option<Vec<_>>>())
        .and_then(|bytes| {
            (bytes.len() == 32 && bytes.iter().all(|byte| *byte <= u8::MAX as u64))
                .then(|| bytes.into_iter().map(|byte| byte as u8).collect::<Vec<_>>())
        });
    Ok(json!({
        "state": admission_state::APPROVAL_PENDING,
        "approvals": approvals,
        "complete": complete,
        "next_after": next_after,
    }))
}

/// Execute a bounded JSON request. Staged security changes require save/readback/adopt.
pub fn execute(handle: i64, bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() > MAX_REQUEST {
        return Err("request exceeds limit".into());
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    serde_json::to_vec(&execute_request(handle, request)?).map_err(|e| e.to_string())
}

// Binary snapshots never pass through the JSON request size bound. Metadata is
// independently bounded and cannot supply a second, ambiguous snapshot value.
/// Execute metadata with a binary snapshot; return metadata and snapshot separately.
/// The caller must durably save and read back staged snapshots before adopting them.
pub fn execute_stored(
    handle: i64,
    metadata: &[u8],
    snapshot: &[u8],
) -> Result<[Vec<u8>; 2], String> {
    if metadata.len() > MAX_REQUEST || snapshot.len() > arachne_security::MAX_SEALED_BUNDLE {
        return Err("stored request exceeds limit".into());
    }
    // Parse original bytes strictly before a generic map can hide duplicate fields.
    let mut request: Request = serde_json::from_slice(metadata).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_slice(metadata).map_err(|e| e.to_string())?;
    let object = value.as_object().ok_or("request must be an object")?;
    if object.contains_key("snapshot") {
        return Err("snapshot must use the binary argument".into());
    }
    let stored = matches!(
        object.get("op").and_then(Value::as_str),
        Some(
            "restore_workspace"
                | "restore_pending_join"
                | "adopt_admission"
                | "adopt_join"
                | "adopt_publication"
                | "adopt_reception"
                | "adopt_recovery"
                | "adopt_current_view"
        )
    );
    let binary_welcome = matches!(request, Request::StageJoin { .. }) && !snapshot.is_empty();
    if binary_welcome {
        if object.contains_key("welcome") {
            return Err("Welcome must have exactly one representation".into());
        }
        if snapshot.len() > arachne_security::MAX_WELCOME {
            return Err("Welcome exceeds binary input bound".into());
        }
        if let Request::StageJoin { welcome, .. } = &mut request {
            *welcome = snapshot.to_vec();
        }
    }
    if !stored && !binary_welcome && !snapshot.is_empty() {
        return Err("operation does not accept a snapshot".into());
    }
    if stored {
        let target = match &mut request {
            Request::RestoreWorkspace { snapshot, .. }
            | Request::RestorePendingJoin { snapshot, .. }
            | Request::AdoptAdmission { snapshot }
            | Request::AdoptJoin { snapshot }
            | Request::AdoptPublication { snapshot }
            | Request::AdoptReception { snapshot }
            | Request::AdoptRecovery { snapshot }
            | Request::AdoptCurrentView { snapshot } => snapshot,
            _ => unreachable!(),
        };
        *target = snapshot.to_vec();
    }
    let mut response = execute_request(handle, request)?;
    // ponytail: current dispatcher builds bounded JSON values internally; move
    // snapshots into a typed result if measured allocation cost warrants it.
    let snapshot = response
        .as_object_mut()
        .and_then(|v| v.remove("snapshot"))
        .map(serde_json::from_value::<Vec<u8>>)
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    if snapshot.len() > arachne_security::MAX_SEALED_BUNDLE {
        return Err("stored response exceeds limit; close and restore".into());
    }
    Ok([
        serde_json::to_vec(&response).map_err(|e| e.to_string())?,
        snapshot,
    ])
}

fn execute_request(handle: i64, request: Request) -> Result<Value, String> {
    let shared = session(handle)?;
    let mut guard = shared.lock().map_err(|_| "node session unavailable")?;
    let busy_before = admission_busy(guard.as_ref().ok_or("node is closed")?);
    let mut ended = None;
    let result = execute_in_session(&mut guard, request, &mut ended);
    // Control requests set aside while a commit was pending raised their
    // signal on arrival, and the host already found nothing it could serve.
    // Wake it again now that they can be served.
    if let Some(session) = guard.as_mut()
        && session.staged_workspace.is_none()
    {
        session.staged_step_received = false;
    }
    if let Some(session) = guard.as_ref()
        && session.staged_workspace.is_none()
        && session.inbound_admission.is_none()
        && !session.admission_queue.is_empty()
    {
        // Intake replies leave the request held while the host commits the
        // next admission. Wake the host for that second, local staging pass.
        session.node.rearm_control_signal();
    }
    if let Some(session) = guard.as_ref()
        && busy_before
        && !admission_busy(session)
        && session.node.has_deferred_controls()
    {
        session.node.rearm_control_signal();
    }
    // A gossiped step held for a later epoch spent its arrival signal. Once
    // the epoch before it lands, wake the host to stage it.
    if let Some(session) = guard.as_ref()
        && !admission_busy(session)
        && session
            .workspace
            .as_ref()
            .is_some_and(|owner| session.gossip_steps_ahead.contains_key(&owner.epoch()))
    {
        session.node.rearm_control_signal();
    }
    // A removal ended the session: release the lock before the blocking
    // shutdown, so other callers fail fast with "node is closed".
    drop(guard);
    if let Some(ended) = ended {
        shutdown_session(ended)?;
    }
    result
}

fn admission_busy(session: &Session) -> bool {
    session.staged_workspace.is_some() || session.inbound_admission.is_some()
}

fn reset_workspace(session: &mut Session) -> Result<Value, String> {
    let changed = session.workspace.is_some()
        || session.pending_join.is_some()
        || session.records.is_some()
        || session.activity.phase != WorkspacePhase::Empty;
    let mut resetting = session.activity.clone();
    resetting.transition(WorkspacePhase::Resetting, Some("reset_requested"))?;
    let reset_presence = presence::Presence::new()?;
    let durable = session.records.is_some();
    if durable {
        persistence::reset_records(session, &resetting)?;
    }

    release_overlay_paths(&DEVICE_OVERLAY_PATHS, session.overlay_paths);
    session.overlay_paths = 0;
    session.presence = reset_presence;
    session.resources = resources::Jobs::default();
    session.interests.cancel();
    session.membership_update = None;
    session.membership_offer = None;
    session.membership_offer_requires_adoption = false;
    session.membership_peer_failures.clear();
    session.staged_step_received = false;
    session.gossip_steps_ahead.clear();
    session.membership_head = None;
    session.range_pull = None;
    session.gossip_counts = Arc::default();
    session.profile_pull = None;
    session.profiles_walked.clear();
    session.gossip_profiles_pending.clear();
    session.cutoff = None;
    session.current_view = None;
    session.ready_current_view = None;
    session.range = None;
    session.ready_range = None;
    session.direct_range = None;
    session.ready_direct_range = None;
    session.direct_miss = None;
    session.recovered.clear();
    session.publisher = None;
    session.received = None;
    session.inbox = None;
    session.inbound_admission = None;
    session.admission_queue = arachne_security::AdmissionQueue::new();
    session.admission_metadata.clear();
    session.admission_waiters = admission_waiters::AdmissionWaiters::new(MAX_ADMISSION_WAITERS);
    session.admission_pushes.clear();
    session.pending_approvals.clear();
    session.staged_approval_id = None;
    session.queued_admission_in_flight.clear();
    session.admission_reads_since_stage = 0;
    session.nearby_workspaces.clear();
    session.staged_workspace = None;
    session.peer_profile_summaries.clear();
    session.staged_removal = None;
    session.workspace = None;
    session.committed.clear();
    session.checkpoint_exchange = None;
    session.join_exchange = None;
    session.pending_join = None;
    session.join_lifecycle = None;
    session.join_history_prefix.clear();
    session.records = None;
    session.activity = WorkspaceActivity::default();

    Ok(json!({
        "state": "reset",
        "changed": changed,
        "durable": durable,
        "reset_activity": resetting.projection(),
        "activity": activity_value(session),
    }))
}

fn discard_workspace_candidate(session: &mut Session) -> Result<Value, String> {
    if session.staged_removal.is_some() {
        return Err("removed membership awaits durable adoption".into());
    }
    if session.inbound_admission.is_some() {
        return Err("received admission awaits adoption or reply".into());
    }
    let discarded = session.staged_workspace.take().is_some();
    let offer_cancelled = session.membership_offer.take().is_some();
    session.membership_offer_requires_adoption = false;
    session.staged_step_received = false;
    Ok(json!({
        "state": "workspace_candidate_discarded",
        "discarded": discarded,
        "offer_cancelled": offer_cancelled,
    }))
}

fn execute_in_session(
    guard: &mut std::sync::MutexGuard<'_, Option<Session>>,
    request: Request,
    ended: &mut Option<Session>,
) -> Result<Value, String> {
    if matches!(request, Request::ResetWorkspace {}) {
        return reset_workspace(guard.as_mut().ok_or("node is closed")?);
    }
    if matches!(request, Request::DiscardWorkspaceCandidate {}) {
        return discard_workspace_candidate(guard.as_mut().ok_or("node is closed")?);
    }
    if matches!(request, Request::DriveWorkspace {}) {
        if guard.as_ref().ok_or("node is closed")?.records.is_none() {
            return Err("workspace lifecycle requires native record storage".into());
        }
        let mut staged =
            execute_in_session(guard, Request::PollAdmission { profile: false }, ended)?;
        let staged_state = staged
            .get("state")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if staged_state.as_deref() != Some("awaiting_save") {
            if staged_state.as_deref() == Some("reply_ready")
                && guard
                    .as_ref()
                    .ok_or("node is closed")?
                    .inbound_admission
                    .is_some()
            {
                let reply = execute_in_session(guard, Request::SendAdmissionReply {}, ended)?;
                staged["state"] = json!("workspace_reply_ready");
                staged["reply_queued"] = reply["queued"].clone();
            }
            // Return the event just drained before attempting optional
            // membership reconciliation. A presence/admission reply is the
            // authoritative result for this host tick; an unrelated query
            // may still be in flight or have reached its own transport
            // deadline and must not hide it.
            if staged_state.is_some() {
                staged["activity"] = activity_value(guard.as_ref().ok_or("node is closed")?);
                return Ok(staged);
            }
            let membership = execute_in_session(guard, Request::PollMembershipUpdate {}, ended)?;
            if !membership.is_null() {
                let state = membership
                    .get("state")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if matches!(
                    state.as_deref(),
                    Some("workspace_name_update_available" | "workspace_name_checkpoint_available")
                ) {
                    let request = if state.as_deref() == Some("workspace_name_update_available") {
                        Request::StageWorkspaceNameUpdate {
                            name_record: serde_json::from_value(membership["name_record"].clone())
                                .map_err(|_| "workspace name record is invalid")?,
                        }
                    } else {
                        Request::StageWorkspaceNameCheckpoint {
                            name_checkpoint: serde_json::from_value(
                                membership["name_checkpoint"].clone(),
                            )
                            .map_err(|_| "workspace name checkpoint is invalid")?,
                        }
                    };
                    let staged_name = execute_in_session(guard, request, ended)?;
                    let snapshot: Vec<u8> = serde_json::from_value(staged_name["snapshot"].clone())
                        .map_err(|_| "workspace name snapshot is invalid")?;
                    {
                        let session = guard.as_mut().ok_or("node is closed")?;
                        persistence::commit_candidate(session, &snapshot)?;
                    }
                    let mut committed =
                        execute_in_session(guard, Request::AdoptAdmission { snapshot }, ended)?;
                    committed["state"] = json!("workspace_name_committed");
                    committed["activity"] = activity_value(guard.as_ref().ok_or("node is closed")?);
                    return Ok(committed);
                }
                let mut membership = membership;
                if matches!(
                    state.as_deref(),
                    Some(
                        "membership_update_available"
                            | "membership_current"
                            | "membership_unavailable"
                            | "membership_peer_behind"
                            | "workspace_name_peer_behind"
                            | "membership_update_stale"
                    )
                ) {
                    membership["membership_state"] = membership["state"].clone();
                    membership["state"] = json!("membership_replied");
                }
                membership["activity"] = activity_value(guard.as_ref().ok_or("node is closed")?);
                return Ok(membership);
            }
            staged["activity"] = activity_value(guard.as_ref().ok_or("node is closed")?);
            return Ok(staged);
        }
        let snapshot: Vec<u8> = serde_json::from_value(staged["snapshot"].clone())
            .map_err(|_| "workspace candidate snapshot is invalid")?;
        {
            let session = guard.as_mut().ok_or("node is closed")?;
            persistence::commit_candidate(session, &snapshot)?;
        }
        let mut committed = execute_in_session(guard, Request::AdoptAdmission { snapshot }, ended)?;
        if guard
            .as_ref()
            .ok_or("node is closed")?
            .inbound_admission
            .is_some()
        {
            let reply = execute_in_session(guard, Request::SendAdmissionReply {}, ended)?;
            committed["reply_queued"] = reply["queued"].clone();
        }
        committed["state"] = json!("workspace_committed");
        committed["activity"] = activity_value(guard.as_ref().ok_or("node is closed")?);
        return Ok(committed);
    }
    if matches!(request, Request::DriveJoin {}) {
        if guard.as_ref().ok_or("node is closed")?.records.is_none() {
            return Err("join lifecycle requires native record storage".into());
        }
        if let Some(incoming) = guard
            .as_mut()
            .ok_or("node is closed")?
            .node
            .poll_control_matching(admission_offer_candidate)
        {
            let peer = incoming.peer();
            let allowed = guard
                .as_ref()
                .ok_or("node is closed")?
                .join_lifecycle
                .as_ref()
                .is_some_and(|lifecycle| {
                    lifecycle.peers.contains(&peer)
                        && lifecycle.selected.is_none_or(|selected| selected == peer)
                });
            if !allowed {
                let _ = incoming.respond(vec![0]);
                return Ok(json!({"state":admission_state::UNAVAILABLE,
                    "reason":"unrecognized_admission_pusher","peer":peer}));
            }
            if let Some(exchange) = guard
                .as_mut()
                .ok_or("node is closed")?
                .join_exchange
                .take()
            {
                exchange.task.abort();
            }
            let packet = incoming.payload().to_vec();
            let (commits, welcome) = match parse_admission_offer(&packet) {
                Ok(value) => value,
                Err(_) => {
                    let _ = incoming.respond(vec![0]);
                    return Ok(json!({"state":admission_state::UNAVAILABLE,
                        "reason":"invalid_admission_offer","peer":peer}));
                }
            };
            let staged = match execute_in_session(
                guard,
                Request::StageJoin { commits, welcome },
                ended,
            ) {
                Ok(staged) => staged,
                Err(_) => {
                    let _ = incoming.respond(vec![0]);
                    return Ok(json!({"state":admission_state::UNAVAILABLE,
                        "reason":"invalid_admission_offer","peer":peer}));
                }
            };
            guard
                .as_mut()
                .ok_or("node is closed")?
                .inbound_admission = Some(incoming);
            return Ok(staged);
        }
        let compact_pending = guard
            .as_ref()
            .ok_or("node is closed")?
            .pending_join
            .as_ref()
            .is_some_and(|pending| pending.admission_request().is_err());
        if compact_pending {
            if let Some(mut exchange) = guard
                .as_mut()
                .ok_or("node is closed")?
                .checkpoint_exchange
                .take()
            {
                if !exchange.task.is_finished() {
                    let peer = exchange.peer;
                    guard.as_mut().ok_or("node is closed")?.checkpoint_exchange = Some(exchange);
                    return Ok(
                        json!({"state":"admission_pending", "phase":"checkpoint", "peer":peer}),
                    );
                }
                match guard
                    .as_ref()
                    .ok_or("node is closed")?
                    .runtime
                    .block_on(&mut exchange.task)
                    .map_err(|_| "checkpoint exchange task cancelled")?
                {
                    Ok(value) => {
                        let checkpoint: Vec<u8> =
                            serde_json::from_value(value["checkpoint"].clone())
                                .map_err(|_| "checkpoint reply is invalid")?;
                        let peer: [u8; 32] = serde_json::from_value(value["peer"].clone())
                            .map_err(|_| "checkpoint peer is invalid")?;
                        let session = guard.as_mut().ok_or("node is closed")?;
                        session
                            .pending_join
                            .as_mut()
                            .ok_or("session has no pending join")?
                            .complete_checkpoint(&checkpoint)
                            .map_err(str::to_owned)?;
                        let lifecycle = session
                            .join_lifecycle
                            .as_mut()
                            .ok_or("join lifecycle has no persisted Iroh peers")?;
                        lifecycle.selected = Some(peer);
                        lifecycle.cursor = lifecycle
                            .peers
                            .iter()
                            .position(|candidate| *candidate == peer)
                            .unwrap_or(lifecycle.cursor);
                        persistence::commit_pending_join(session)?;
                    }
                    Err(reason) => {
                        let session = guard.as_mut().ok_or("node is closed")?;
                        let lifecycle = session
                            .join_lifecycle
                            .as_mut()
                            .ok_or("join lifecycle has no persisted Iroh peers")?;
                        if lifecycle.selected == Some(exchange.peer) {
                            lifecycle.advance();
                            persistence::commit_pending_join(session)?;
                        }
                        tracing::debug!(
                            target: "data_fabric_transport",
                            peer = ?exchange.peer,
                            %reason,
                            "CHECKPOINT_EXCHANGE_FAILED"
                        );
                        return Ok(json!({"state":admission_state::UNAVAILABLE,
                            "reason":"checkpoint_unavailable", "peer":exchange.peer}));
                    }
                }
            } else {
                let (peers, invitation, selected) = {
                    let session = guard.as_mut().ok_or("node is closed")?;
                    let lifecycle = session
                        .join_lifecycle
                        .as_ref()
                        .ok_or("join lifecycle has no persisted Iroh peers")?;
                    let mut peers = Vec::with_capacity(lifecycle.peers.len());
                    if let Some(selected) = lifecycle.selected {
                        peers.push(selected);
                    }
                    for peer in lifecycle.peers.iter().skip(lifecycle.cursor) {
                        if !peers.contains(peer) {
                            peers.push(*peer);
                        }
                    }
                    let selected = *peers.first().ok_or("no reachable workspace member")?;
                    let invitation = session
                        .pending_join
                        .as_ref()
                        .ok_or("session has no pending join")?
                        .deferred_invitation()
                        .map_err(str::to_owned)?
                        .to_vec();
                    (peers, invitation, selected)
                };
                {
                    let session = guard.as_mut().ok_or("node is closed")?;
                    let lifecycle = session
                        .join_lifecycle
                        .as_mut()
                        .ok_or("join lifecycle has no persisted Iroh peers")?;
                    lifecycle.selected = Some(selected);
                    persistence::commit_pending_join(session)?;
                }
                let wake = guard
                    .as_ref()
                    .ok_or("node is closed")?
                    .node
                    .control_signal();
                let client = guard
                    .as_ref()
                    .ok_or("node is closed")?
                    .node
                    .control_client();
                let requester = guard.as_ref().ok_or("node is closed")?.node.id();
                let task = guard
                    .as_ref()
                    .ok_or("node is closed")?
                    .runtime
                    .spawn(async move {
                        let outcome =
                            request_invitation_checkpoint(client, requester, invitation, peers)
                                .await;
                        wake.notify_one();
                        outcome
                    });
                guard.as_mut().ok_or("node is closed")?.checkpoint_exchange =
                    Some(PendingCheckpointExchange {
                        peer: selected,
                        task,
                    });
                return Ok(
                    json!({"state":"admission_pending", "phase":"checkpoint", "peer":selected}),
                );
            }
        }
        let mut reply = None;
        if let Some(mut exchange) = guard.as_mut().ok_or("node is closed")?.join_exchange.take() {
            if !exchange.task.is_finished() {
                let peer = exchange.peer;
                guard.as_mut().ok_or("node is closed")?.join_exchange = Some(exchange);
                return Ok(json!({"state":"admission_pending", "peer":peer}));
            }
            let outcome = guard
                .as_ref()
                .ok_or("node is closed")?
                .runtime
                .block_on(&mut exchange.task)
                .map_err(|_| "join exchange task cancelled")?;
            match outcome {
                JoinAttemptOutcome::NotSent => {
                    let session = guard.as_mut().ok_or("node is closed")?;
                    let lifecycle = session
                        .join_lifecycle
                        .as_mut()
                        .ok_or("join lifecycle has no persisted Iroh peers")?;
                    if lifecycle.selected == Some(exchange.peer) {
                        lifecycle.advance();
                        persistence::commit_pending_join(session)?;
                    }
                }
                JoinAttemptOutcome::Waiting => {
                    return Ok(json!({"state":admission_state::WAITING, "peer":exchange.peer}));
                }
                JoinAttemptOutcome::Failed(reason) => {
                    tracing::debug!(
                        target: "data_fabric_transport",
                        peer = ?exchange.peer,
                        %reason,
                        "JOIN_EXCHANGE_FAILED"
                    );
                    return Ok(json!({"state":admission_state::UNAVAILABLE,
                        "reason":"invalid_admission_reply", "peer":exchange.peer}));
                }
                JoinAttemptOutcome::Reply {
                    value,
                    history_prefix,
                } => {
                    let session = guard.as_mut().ok_or("node is closed")?;
                    session.join_history_prefix = history_prefix;
                    reply = Some(value);
                }
            }
        }
        if let Some(reply) = reply {
            if reply.get("state").is_some() {
                return Ok(reply);
            }
            let commits = if let Some(commits) = reply.get("commits") {
                serde_json::from_value(commits.clone())
                    .map_err(|_| "admission reply commits are invalid")?
            } else {
                serde_json::from_value(json!([{
                    "commit": reply["commit"].clone(),
                    "authorization": reply["authorization"].clone(),
                }]))
                .map_err(|_| "admission reply is incomplete")?
            };
            let welcome = serde_json::from_value(reply["welcome"].clone())
                .map_err(|_| "admission reply has no Welcome")?;
            let staged = execute_in_session(guard, Request::StageJoin { commits, welcome }, ended)?;
            let snapshot: Vec<u8> = serde_json::from_value(staged["snapshot"].clone())
                .map_err(|_| "join candidate snapshot is invalid")?;
            {
                let session = guard.as_mut().ok_or("node is closed")?;
                persistence::commit_candidate(session, &snapshot)?;
            }
            let mut joined = execute_in_session(guard, Request::AdoptJoin { snapshot }, ended)?;
            joined["state"] = json!("workspace_joined");
            return Ok(joined);
        }

        let (peer, request, name, checkpoint) = {
            let session = guard.as_mut().ok_or("node is closed")?;
            let lifecycle = session
                .join_lifecycle
                .as_mut()
                .ok_or("join lifecycle has no persisted Iroh peers")?;
            let peer = lifecycle
                .selected
                .or_else(|| lifecycle.peers.get(lifecycle.cursor).copied());
            let Some(peer) = peer else {
                return Ok(json!({"state":admission_state::UNAVAILABLE,
                    "reason":"no_reachable_member"}));
            };
            if lifecycle.selected.is_none() {
                lifecycle.selected = Some(peer);
                persistence::commit_pending_join(session)?;
            }
            let pending = session
                .pending_join
                .as_ref()
                .ok_or("session has no pending join")?;
            (
                peer,
                pending.admission_request().map_err(str::to_owned)?.to_vec(),
                pending.member().display_name().as_bytes().to_vec(),
                pending
                    .admission_checkpoint()
                    .map_err(str::to_owned)?
                    .to_vec(),
            )
        };
        let wake = guard
            .as_ref()
            .ok_or("node is closed")?
            .node
            .control_signal();
        let client = guard
            .as_ref()
            .ok_or("node is closed")?
            .node
            .control_client();
        let task = guard
            .as_ref()
            .ok_or("node is closed")?
            .runtime
            .spawn(async move {
                let outcome = request_join_exchange(client, peer, request, name, checkpoint).await;
                wake.notify_one();
                outcome
            });
        guard.as_mut().ok_or("node is closed")?.join_exchange =
            Some(PendingJoinExchange { peer, task });
        return Ok(json!({"state":"admission_pending", "peer":peer}));
    }
    let session = guard.as_mut().ok_or("node is closed")?;
    if matches!(request, Request::WorkspaceState {}) {
        let mut value = json!({
            "activity": activity_value(session),
            "workspace_ready": session.workspace.is_some(),
            "durable": session.records.is_some(),
        });
        if let Some(owner) = &session.workspace {
            value["workspace"] = json!(owner.id());
        } else if let Some(pending) = &session.pending_join {
            value["workspace"] = json!(pending.workspace_id());
        }
        return Ok(value);
    }
    if matches!(request, Request::WorkspaceMetrics {}) {
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        let roster = owner.member_roster().map_err(str::to_owned)?;
        let metrics = session.node.transport_metrics();
        let paths: Vec<_> = metrics
            .paths
            .iter()
            .filter_map(|path| {
                let member = roster
                    .iter()
                    .find(|member| member.endpoint == path.endpoint)?;
                Some(json!({"member":member.id, "route":path.route, "rtt_ms":path.rtt_ms}))
            })
            .collect();
        return Ok(json!({
            "workspace":owner.id(), "session":session.node.id(),
            "received_bytes":metrics.received_bytes, "sent_bytes":metrics.sent_bytes,
            "receive_queue":metrics.receive_queue,
            "admission_queue":session.admission_queue.len(),
            "admission_queue_bytes":session.admission_queue.bytes(),
            "admission_waiters":session.admission_waiters.len(),
            "control_timing":session.node.control_timing(),
            "membership_gossip":session.gossip_counts.json(),
            "connection_capacity":session.node.connection_capacity(),
            "gossip_neighbors":session.runtime.block_on(session.node.live_neighbors(owner.id())).len(),
            "admission_in_flight":session.queued_admission_in_flight.len(),
            "approval_pending":session.pending_approvals.len(),
            "activity":activity_value(session),
            "pending_objects":session.inbox.as_ref().map(|inbox| inbox.pending_count()).unwrap_or(0) + session.recovered.len(),
            "repair_jobs":usize::from(session.cutoff.is_some()) + usize::from(session.range.is_some() || session.ready_range.is_some())
                + usize::from(session.direct_range.is_some() || session.ready_direct_range.is_some())
                + usize::from(session.current_view.is_some() || session.ready_current_view.is_some()),
            "paths":paths, "paths_limited":metrics.paths_limited
        }));
    }
    if matches!(request, Request::NetworkChange {}) {
        session.runtime.block_on(session.node.network_change());
        session.interests.repair();
        return Ok(json!({"notified":true}));
    }
    if matches!(request, Request::NearbyEndpoints {}) {
        let peers = session.runtime.block_on(session.node.nearby_peers());
        let names = session.runtime.block_on(async {
            let mut queries = tokio::task::JoinSet::new();
            for peer in &peers {
                let peer = *peer;
                let request = session.node.request_control(peer, NEARBY_IDENTITY);
                queries.spawn(async move {
                    tokio::time::timeout(Duration::from_millis(750), request)
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .and_then(|reply| String::from_utf8(reply).ok())
                        .map(|name| json!({"id": peer, "name": name}))
                });
            }
            let mut names = Vec::new();
            while let Some(Ok(Some(name))) = queries.join_next().await {
                names.push(name);
            }
            names
        });
        return Ok(json!({"endpoints":peers,"names":names}));
    }
    if matches!(request, Request::NearbyWorkspaces {}) {
        let peers = session
            .runtime
            .block_on(session.node.nearby_workspace_peers());
        let peer_count = peers.len();
        let (found, checked) = session.runtime.block_on(async {
            let mut queries = tokio::task::JoinSet::new();
            for peer in peers {
                let request = session.node.request_control(peer, NEARBY_WORKSPACE);
                queries.spawn(async move {
                    tokio::time::timeout(Duration::from_secs(3), request)
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .map(|reply| (peer, reply))
                });
            }
            let mut advertisements = BTreeMap::<Vec<u8>, Value>::new();
            let mut checked = 0usize;
            while let Some(Ok(Some((peer, reply)))) = queries.join_next().await {
                checked += 1;
                for payload in nearby_workspace_payloads(&reply) {
                    let Some((&mode, payload)) = payload.split_first() else {
                        continue;
                    };
                    let (workspace_name, invitation) = match mode {
                        1 | 2 => (None, payload),
                        3 | 4 if payload.len() >= 2 => {
                            let length = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                            if !(1..=320).contains(&length) || payload.len() < length + 2 { continue; }
                            let Ok(name) = std::str::from_utf8(&payload[2..2 + length]) else { continue; };
                            if arachne_security::validate_workspace_name(name).is_err() { continue; }
                            (Some(name), &payload[2 + length..])
                        }
                        _ => continue,
                    };
                    if invitation.is_empty() || invitation.len() > 2048 {
                        continue;
                    }
                    advertisements
                        .entry(invitation.to_vec())
                        .or_insert_with(|| {
                            json!({
                                "peer": peer,
                                "mode": if mode == 1 || mode == 3 { "request_access" } else { "open_joining" },
                                "workspace_name": workspace_name,
                                "invitation": invitation,
                            })
                        });
                }
            }
            (advertisements.into_values().collect::<Vec<_>>(), checked)
        });
        return Ok(json!({"workspaces":found,"endpoints_checked":checked,
            "limited":peer_count == 16 || checked < peer_count}));
    }
    if let Request::SetNearbyWorkspace {
        mode,
        invitation,
        workspace_name,
        workspace,
    } = &request
    {
        if let Some(name) = workspace_name {
            arachne_security::validate_workspace_name(name).map_err(str::to_owned)?;
        }
        let encoded = match mode.as_deref() {
            None if invitation.is_empty() && workspace_name.is_none() => None,
            Some("request_access" | "open_joining")
                if !invitation.is_empty() && invitation.len() <= 2048 =>
            {
                let mut value = vec![
                    if mode.as_deref() == Some("request_access") {
                        1
                    } else {
                        2
                    } + if workspace_name.is_some() { 2 } else { 0 },
                ];
                if let Some(name) = workspace_name {
                    value.extend((name.len() as u16).to_be_bytes());
                    value.extend(name.as_bytes());
                }
                value.extend(invitation);
                Some(value)
            }
            _ => return Err("invalid nearby workspace advertisement".into()),
        };
        if let Some(encoded) = encoded {
            let key = nearby_workspace_key(*workspace, invitation);
            if !session.nearby_workspaces.contains_key(&key)
                && session.nearby_workspaces.len() >= MAX_NEARBY_WORKSPACES
            {
                return Err("nearby workspace advertisement limit reached".into());
            }
            session.nearby_workspaces.insert(key, encoded);
        } else if let Some(workspace) = workspace {
            session.nearby_workspaces.remove(workspace);
        } else {
            session.nearby_workspaces.clear();
        }
        return Ok(json!({"state":if session.nearby_workspaces.is_empty() {
            "nearby_workspace_private"
        } else {
            "nearby_workspace_advertised"
        }}));
    }
    if let Request::SetNearbyIdentity { name } = &request {
        arachne_security::validate_workspace_name(name).map_err(str::to_owned)?;
        session.nearby_identity = Some(name.trim().to_owned());
        return Ok(json!({"state":"nearby_identity_set"}));
    }
    if let Request::SendNearbyInvitation { peer, invitation } = &request {
        if invitation.is_empty() || invitation.len() > 2048 {
            return Err("invalid nearby invitation length".into());
        }
        let mut packet = NEARBY_INVITATION.to_vec();
        packet.extend((invitation.len() as u16).to_be_bytes());
        packet.extend(invitation);
        let reply = session
            .runtime
            .block_on(session.node.request_control(*peer, &packet))
            .map_err(|error| error.to_string())?;
        if reply != [1] {
            return Err("nearby device rejected invitation".into());
        }
        return Ok(json!({"state":"nearby_invitation_sent","peer":peer}));
    }
    if let Some((removed, expected)) = &session.staged_removal {
        let Request::AdoptAdmission { snapshot } = request else {
            return Err("removed membership awaits durable adoption".into());
        };
        if &snapshot != expected {
            return Err("removed snapshot does not match candidate".into());
        }
        if let Some(store) = &session.records {
            store.require_committed(&snapshot)?;
        }
        let value = json!({"workspace":removed.workspace_id(), "epoch":removed.epoch(),
            "state":"removed", "workspace_ready":false, "member":{"id":removed.member().id(),
            "display_name":removed.member().display_name()}, "commit_digest":removed.commit_digest()});
        *ended = Some(guard.take().ok_or("node is closed")?);
        return Ok(value);
    }
    if !session.recovered.is_empty() && !matches!(request, Request::PollRecoveredPublication {}) {
        return Err("drain adopted recovery publications before another operation".into());
    }
    if session.staged_workspace.is_some()
        && !matches!(
            request,
            Request::AdoptAdmission { .. }
                | Request::AdoptJoin { .. }
                | Request::AdoptPublication { .. }
                | Request::AdoptReception { .. }
                | Request::AdoptRecovery { .. }
                | Request::AdoptCurrentView { .. }
                | Request::PollAdmission { .. }
                | Request::OfferStagedMembershipUpdate { .. }
                | Request::PollMembershipOffer {}
                | Request::DiscardWorkspaceCandidate {}
        )
    {
        return Err(
            "workspace candidate awaits durable adoption; close and restore saved state to recover"
                .into(),
        );
    }
    if session.inbound_admission.is_some()
        && !matches!(
            request,
            Request::AdoptAdmission { .. }
                | Request::AdoptJoin { .. }
                | Request::SendAdmissionReply {}
                | Request::PollAdmission { .. }
        )
    {
        return Err("received admission awaits adoption or reply; close to recover".into());
    }
    // Recovery and live applications share the receiver ratchets. Leave queued
    // traffic untouched until the requested range is resolved or cancelled.
    if session.inbox.is_none()
        && (session.cutoff.is_some() || session.range.is_some() || session.ready_range.is_some())
    {
        match request {
            Request::PollProtected {} => return Ok(Value::Null),
            Request::StageReception { .. } => {
                return Err("recovery must finish before live reception".into());
            }
            _ => (),
        }
    }
    if let Request::Resource { request } = request {
        return resources::execute(session, request);
    }
    if session.workspace.is_some() && matches!(request, Request::Publish { .. }) {
        return Err("unprotected publication is disabled for an admitted workspace".into());
    }
    if session.workspace.is_some() && matches!(request, Request::InstallVerifiedPolicy { .. }) {
        return Err("admitted workspace routing must derive from verified membership".into());
    }
    if session.workspace.is_some() && matches!(request, Request::Poll {}) {
        return Err("use poll_protected for an admitted workspace".into());
    }
    let value = if matches!(request, Request::EndpointInfo {}) {
        json!({"endpoint_key":session.node.id(), "bound_address":session.node.address().to_string()})
    } else if let Request::ControlExchange {
        peer,
        address,
        payload,
    } = request
    {
        if let Some(address) = address {
            let address: std::net::SocketAddr =
                address.parse().map_err(|_| "invalid address hint")?;
            session
                .runtime
                .block_on(session.node.add_address_hint(peer, address))
                .map_err(|e| e.to_string())?;
        }
        let reply = session
            .runtime
            .block_on(session.node.request_control(peer, &payload))
            .map_err(|e| e.to_string())?;
        json!({"reply": reply})
    } else if let Request::PollWorkspacePresence { announce } = request {
        presence::poll(session, announce)?
    } else if matches!(
        request,
        Request::FetchMembershipUpdate { .. }
            | Request::PollMembershipUpdate {}
            | Request::NextMembershipPeer { .. }
            | Request::OfferMembershipUpdate { .. }
            | Request::OfferStagedMembershipUpdate { .. }
            | Request::PollMembershipOffer {}
    ) {
        membership::poll(session, request)?
    } else if matches!(
        request,
        Request::EnableObjectDelivery {}
            | Request::PollPendingObject { .. }
            | Request::StageObjectAcknowledgement { .. }
            | Request::StageObjectRejection { .. }
    ) {
        protected::inbox_operation(session, request)?
    } else if matches!(
        request,
        Request::StageNetworkPublication { .. } | Request::PollProtected {}
    ) {
        protected::stage(session, request)?
    } else if matches!(
        request,
        Request::StagePublication { .. } | Request::StageReception { .. }
    ) {
        if session.inbox.is_some() {
            return Err("raw MLS applications disabled after object cutover".into());
        }
        let original = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        let key = session
            .storage_key
            .as_ref()
            .ok_or("session has no protected root key")?;
        let mut candidate = original.provisional_copy().map_err(str::to_owned)?;
        let (transition, state) = match request {
            Request::StagePublication { context, payload } => (
                WorkspaceTransition::Publication(
                    candidate
                        .protect_application(&context, &payload)
                        .map_err(str::to_owned)?,
                ),
                "awaiting_publication_save",
            ),
            Request::StageReception {
                context,
                ciphertext,
            } => (
                WorkspaceTransition::Reception(
                    candidate
                        .unprotect_application(&context, &ciphertext)
                        .map_err(str::to_owned)?,
                ),
                "awaiting_reception_save",
            ),
            _ => unreachable!(),
        };
        let snapshot = seal_state(
            session.records.is_some(),
            &candidate,
            key,
            session.publisher.as_ref(),
            session.received.as_ref(),
            session.inbox.as_ref(),
        )?;
        let value = json!({"workspace":candidate.id(), "snapshot":snapshot, "state":state, "durable":false});
        session.staged_workspace = Some(StagedWorkspace {
            publisher: session.publisher.clone(),
            received: session.received.clone(),
            inbox: session.inbox.clone(),
            transition,
            workspace: candidate,
            snapshot,
        });
        value
    } else if let Request::StageRecoveryRange { retain_until } = request {
        protected::stage_recovery(session, retain_until)?
    } else if matches!(request, Request::PollRecoveredPublication {}) {
        match session.recovered.pop_front() {
            Some((context, message)) => json!({"workspace":context.workspace,
                "revision":context.revision, "topic":context.topic.as_str(), "id":context.id,
                "sequence":context.sequence.map(|n| n.get()),
                "payload":message.payload, "member":message.member, "endpoint":message.endpoint}),
            None => Value::Null,
        }
    } else if let Request::FetchRecoveryRange {
        peer,
        author,
        revision,
        topics,
        after,
        through,
    } = request
    {
        if session.cutoff.is_some()
            || session.range.is_some()
            || session.ready_range.is_some()
            || session.direct_range.is_some()
            || session.ready_direct_range.is_some()
            || session.current_view.is_some()
            || session.ready_current_view.is_some()
        {
            return Err("recovery operation already pending".into());
        }
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        if peer == Some(session.node.id())
            || topics.is_empty()
            || topics.len() > arachne_delivery::MAX_TOPICS
            || matches!((after, through), (Some(after), Some(through)) if after >= through)
            || matches!((after, through), (Some(_), None) | (None, Some(_)))
        {
            return Err("invalid recovery peer, selection or range".into());
        }
        let count = topics.len();
        let topics = topics
            .into_iter()
            .map(Topic::new)
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|e| e.to_string())?;
        if topics.len() != count {
            return Err("duplicate recovery topic".into());
        }
        let author = match (author, peer) {
            (Some(author), _) => owner
                .endpoints_for_members(&[author])
                .map(|_| author)
                .map_err(str::to_owned),
            (None, Some(peer)) => owner.member_id_for_endpoint(peer).map_err(str::to_owned),
            (None, None) => Err("automatic recovery requires an original author".into()),
        }?;
        let after = match after {
            Some(after) => after,
            None => session
                .inbox
                .as_ref()
                .ok_or("automatic recovery requires object delivery")?
                .recovery_progress(author, &topics),
        };
        let available = through
            .is_none()
            .then(|| arachne_delivery::wire::AvailableRangeQuery {
                workspace: owner.id(),
                author,
                epoch: owner.epoch(),
                policy_revision: revision,
                after,
                topics: topics.clone(),
            });
        let query = arachne_delivery::RangeQuery {
            workspace: owner.id(),
            author,
            epoch: owner.epoch(),
            policy_revision: revision,
            after,
            through: through.unwrap_or_else(|| after.saturating_add(1)),
            topics,
        };
        if query.after == query.through {
            return Err("recovery cursor exhausted".into());
        }
        let automatic = available.is_some() || peer.is_none();
        let mut candidates = if automatic {
            session
                .runtime
                .block_on(session.node.live_neighbors(query.workspace))
        } else {
            vec![peer.unwrap()]
        };
        if automatic {
            candidates.sort_unstable();
            candidates.dedup();
            candidates.truncate(MAX_WORKSPACE_OVERLAY_PATHS);
            let author_endpoint = owner
                .endpoints_for_members(&[query.author])
                .map_err(str::to_owned)?[0];
            if author_endpoint != session.node.id()
                && !candidates.contains(&author_endpoint)
                && (session.node.can_dial_by_peer_id()
                    || session
                        .runtime
                        .block_on(session.node.address_hint(author_endpoint))
                        .is_some())
            {
                candidates.insert(0, author_endpoint);
            }
            candidates.retain(|candidate| {
                check_recovery_policy(
                    session,
                    *candidate,
                    query.author,
                    query.workspace,
                    query.epoch,
                    revision,
                    &query.topics,
                )
                .is_ok()
            });
        } else {
            check_recovery_policy(
                session,
                candidates[0],
                query.author,
                query.workspace,
                query.epoch,
                revision,
                &query.topics,
            )?;
        }
        if candidates.is_empty() {
            return Ok(json!({"state":"recovery_source_waiting", "accepted_progress":false}));
        }
        let wire = match &available {
            Some(request) => request.to_wire(),
            None => query.to_wire(),
        }
        .map_err(str::to_owned)?;
        let requests = candidates
            .iter()
            .map(|peer| (*peer, session.node.request_control(*peer, &wire)))
            .collect::<Vec<_>>();
        let candidate_count = requests.len();
        let (reply_tx, replies) = mpsc::channel(candidate_count);
        let task = session.runtime.spawn(async move {
            let mut pending = tokio::task::JoinSet::new();
            for (peer, request) in requests {
                pending.spawn(async move { (peer, request.await.map_err(|e| e.to_string())) });
            }
            while let Some(result) = pending.join_next().await {
                if let Ok(reply) = result
                    && reply_tx.send(reply).await.is_err()
                {
                    break;
                }
            }
        });
        session.range = Some(PendingRange {
            query,
            available,
            automatic,
            replies,
            task,
            attempted: 0,
            reason: None,
        });
        json!({"state":"recovery_range_pending", "candidate_count":candidate_count,
            "automatic_source":automatic, "accepted_progress":false})
    } else if matches!(request, Request::CancelRecoveryRange {}) {
        drop(session.range.take());
        session.ready_range = None;
        json!({"state":"recovery_range_cancelled", "accepted_progress":false})
    } else if matches!(request, Request::PollRecoveryRange {}) {
        let Some(active) = session.range.as_mut() else {
            return Ok(Value::Null);
        };
        let (peer, reply) = match active.replies.try_recv() {
            Ok(reply) => reply,
            Err(mpsc::error::TryRecvError::Empty) if !active.task.is_finished() => {
                return Ok(Value::Null);
            }
            Err(_) => {
                let mut pending = session.range.take().unwrap();
                if pending.automatic {
                    return Ok(json!({"state":"recovery_source_unavailable",
                        "attempted":pending.attempted,
                        "reason":pending.reason.take().unwrap_or_else(|| "no current holder supplied authenticated coverage".into()),
                        "automatic_source":true, "accepted_progress":false}));
                }
                return Err(pending
                    .reason
                    .take()
                    .unwrap_or_else(|| "recovery request failed".into()));
            }
        };
        active.attempted += 1;
        let query = active.query.clone();
        let available = active.available.clone();
        let automatic = active.automatic;
        let attempted = active.attempted;
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        if !automatic {
            drop(session.range.take());
            check_recovery_policy(
                session,
                peer,
                query.author,
                query.workspace,
                query.epoch,
                query.policy_revision,
                &query.topics,
            )?;
            let reply = reply?;
            match arachne_delivery::wire::verify_reply(owner, &query, &reply)
                .map_err(str::to_owned)?
            {
                arachne_delivery::wire::RangeReply::Rejected(error) => {
                    json!({"state":"recovery_range_rejected", "reason":error.to_string(), "accepted_progress":false})
                }
                arachne_delivery::wire::RangeReply::Offered(range) => {
                    let packet_count = range.packets().len();
                    drop(range);
                    session.ready_range = Some(ReadyRange {
                        query,
                        peer,
                        reply,
                        packet_count,
                        automatic: false,
                    });
                    let ready = session.ready_range.as_ref().unwrap();
                    json!({"state":"recovery_range_ready", "workspace":ready.query.workspace, "author":ready.query.author,
                        "peer":ready.peer, "epoch":ready.query.epoch, "revision":ready.query.policy_revision,
                        "after":ready.query.after, "through":ready.query.through, "packet_count":ready.packet_count,
                        "retained_bytes":ready.reply.len(), "automatic_source":false, "accepted_progress":false})
                }
            }
        } else {
            let result = check_recovery_policy(
                session,
                peer,
                query.author,
                query.workspace,
                query.epoch,
                query.policy_revision,
                &query.topics,
            )
            .and_then(|_| {
                reply
                    .map_err(|_| "reachable holder did not answer".into())
                    .and_then(|reply| {
                        let (query, reply) = match &available {
                            Some(request) => {
                                arachne_delivery::wire::parse_available_reply(request, &reply)
                                    .map_err(|_| {
                                        "holder returned invalid recovery evidence".to_string()
                                    })?
                                    .ok_or_else(|| "holder has no retained range".to_string())?
                            }
                            None => (query.clone(), reply),
                        };
                        match arachne_delivery::wire::verify_reply(owner, &query, &reply) {
                            Ok(arachne_delivery::wire::RangeReply::Offered(range)) => {
                                Ok((query, reply, range.packets().len()))
                            }
                            Ok(arachne_delivery::wire::RangeReply::Rejected(error)) => {
                                Err(error.to_string())
                            }
                            Err(_) => Err("holder returned invalid recovery evidence".into()),
                        }
                    })
            });
            if let Ok((query, reply, packet_count)) = result {
                drop(session.range.take());
                session.ready_range = Some(ReadyRange {
                    query,
                    peer,
                    reply,
                    packet_count,
                    automatic: true,
                });
                let ready = session.ready_range.as_ref().unwrap();
                json!({"state":"recovery_range_ready", "workspace":ready.query.workspace, "author":ready.query.author,
                    "peer":ready.peer, "epoch":ready.query.epoch, "revision":ready.query.policy_revision,
                    "after":ready.query.after, "through":ready.query.through, "packet_count":ready.packet_count,
                    "retained_bytes":ready.reply.len(), "automatic_source":true, "attempted":attempted,
                    "accepted_progress":false})
            } else {
                session.range.as_mut().unwrap().reason = result.err();
                Value::Null
            }
        }
    } else if matches!(request, Request::NextDirectGap {}) {
        match session
            .inbox
            .as_ref()
            .ok_or("object delivery not enabled")?
            .next_direct_gap(
                session
                    .workspace
                    .as_ref()
                    .ok_or("session has no workspace")?,
            )
            .map_err(str::to_owned)?
        {
            Some(gap) => json!({"state":"direct_recovery_needed", "author":gap.author,
                "revision":gap.revision, "topic":gap.topic.as_str(),
                "recipients":gap.recipients, "after":gap.after, "through":gap.through}),
            None => Value::Null,
        }
    } else if let Request::FetchDirectRecovery {
        author,
        revision,
        topic,
        recipients,
        after,
        through,
    } = request
    {
        if session.cutoff.is_some()
            || session.range.is_some()
            || session.ready_range.is_some()
            || session.direct_range.is_some()
            || session.ready_direct_range.is_some()
            || session.current_view.is_some()
            || session.ready_current_view.is_some()
        {
            return Err("continuity operation already pending".into());
        }
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        let local = owner.member().ok_or("member required")?.id();
        if session.inbox.is_none()
            || !recipients.contains(&local)
            || recipients.len() > 64
            || recipients.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("invalid direct recovery audience".into());
        }
        let query = arachne_delivery::wire::DirectRangeQuery {
            workspace: owner.id(),
            author,
            epoch: owner.epoch(),
            policy_revision: revision,
            topic: Topic::new(topic).map_err(|e| e.to_string())?,
            recipients,
            after,
            through,
        };
        session.direct_miss = None;
        let wire = query.to_wire().map_err(str::to_owned)?;
        let topics = BTreeSet::from([query.topic.clone()]);
        let mut candidates = owner
            .endpoints_for_members(&query.recipients)
            .map_err(str::to_owned)?;
        candidates.extend(
            owner
                .endpoints_for_members(&[query.author])
                .map_err(str::to_owned)?,
        );
        candidates.sort_unstable();
        candidates.dedup();
        candidates.retain(|candidate| {
            *candidate != session.node.id()
                && check_recovery_policy(
                    session,
                    *candidate,
                    query.author,
                    query.workspace,
                    query.epoch,
                    query.policy_revision,
                    &topics,
                )
                .is_ok()
        });
        if candidates.is_empty() {
            return Ok(json!({"state":"direct_recovery_source_waiting",
                "accepted_progress":false}));
        }
        let requests = candidates
            .iter()
            .map(|peer| (*peer, session.node.request_control(*peer, &wire)))
            .collect::<Vec<_>>();
        let candidate_count = requests.len();
        let (reply_tx, replies) = mpsc::channel(candidate_count);
        let task = session.runtime.spawn(async move {
            let mut pending = tokio::task::JoinSet::new();
            for (peer, request) in requests {
                pending.spawn(async move { (peer, request.await.map_err(|e| e.to_string())) });
            }
            while let Some(result) = pending.join_next().await {
                if let Ok(reply) = result
                    && reply_tx.send(reply).await.is_err()
                {
                    break;
                }
            }
        });
        session.direct_range = Some(PendingDirectRange {
            query,
            replies,
            task,
            attempted: 0,
            reason: None,
        });
        json!({"state":"direct_recovery_pending", "candidate_count":candidate_count,
            "accepted_progress":false})
    } else if matches!(request, Request::CancelDirectRecovery {}) {
        drop(session.direct_range.take());
        session.ready_direct_range = None;
        session.direct_miss = None;
        json!({"state":"direct_recovery_cancelled", "accepted_progress":false})
    } else if matches!(request, Request::PollDirectRecovery {}) {
        let Some(active) = session.direct_range.as_mut() else {
            return Ok(Value::Null);
        };
        let (peer, reply) = match active.replies.try_recv() {
            Ok(reply) => reply,
            Err(mpsc::error::TryRecvError::Empty) if !active.task.is_finished() => {
                return Ok(Value::Null);
            }
            Err(_) => {
                let mut pending = session.direct_range.take().unwrap();
                session.direct_miss = Some(pending.query.clone());
                return Ok(json!({"state":"direct_recovery_source_unavailable",
                    "attempted":pending.attempted,
                    "reason":pending.reason.take().unwrap_or_else(||
                        "no intended recipient supplied the missing range".into()),
                    "accepted_progress":false}));
            }
        };
        active.attempted += 1;
        let query = active.query.clone();
        let attempted = active.attempted;
        let result = reply.and_then(|reply| {
            let owner = session
                .workspace
                .as_ref()
                .ok_or("session has no workspace")?;
            check_recovery_policy(
                session,
                peer,
                query.author,
                query.workspace,
                query.epoch,
                query.policy_revision,
                &BTreeSet::from([query.topic.clone()]),
            )?;
            match arachne_delivery::wire::verify_direct_reply(owner, &query, &reply)
                .map_err(str::to_owned)?
            {
                arachne_delivery::wire::DirectRangeReply::Offered(packets) => {
                    Ok((reply, packets.len()))
                }
                arachne_delivery::wire::DirectRangeReply::Unavailable => {
                    Err("intended recipient has no retained range".into())
                }
            }
        });
        if let Ok((reply, packet_count)) = result {
            drop(session.direct_range.take());
            session.ready_direct_range = Some(ReadyDirectRange {
                query,
                peer,
                reply,
                packet_count,
            });
            let ready = session.ready_direct_range.as_ref().unwrap();
            json!({"state":"direct_recovery_ready", "workspace":ready.query.workspace,
                "author":ready.query.author, "peer":ready.peer, "epoch":ready.query.epoch,
                "revision":ready.query.policy_revision, "topic":ready.query.topic.as_str(),
                "after":ready.query.after, "through":ready.query.through,
                "packet_count":ready.packet_count, "retained_bytes":ready.reply.len(),
                "attempted":attempted, "accepted_progress":false})
        } else {
            session.direct_range.as_mut().unwrap().reason = result.err();
            Value::Null
        }
    } else if matches!(request, Request::StageDirectRecovery {}) {
        protected::stage_direct_recovery(session)?
    } else if matches!(request, Request::StageDirectMiss {}) {
        protected::stage_direct_miss(session)?
    } else if let Request::FetchCurrentView {
        peer,
        authority,
        revision,
        topic,
        selector,
    } = request
    {
        if session.current_view.is_some()
            || session.ready_current_view.is_some()
            || session.cutoff.is_some()
            || session.range.is_some()
            || session.ready_range.is_some()
            || session.direct_range.is_some()
            || session.ready_direct_range.is_some()
        {
            return Err("continuity operation already pending".into());
        }
        if peer == Some(session.node.id()) || session.inbox.is_none() {
            return Err("invalid current-view request".into());
        }
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        let topic = Topic::new(topic).map_err(|e| e.to_string())?;
        let topics = BTreeSet::from([topic.clone()]);
        let authority_endpoint = owner
            .endpoints_for_members(&[authority])
            .map_err(str::to_owned)?[0];
        let query = arachne_delivery::current::CurrentViewQuery {
            workspace: owner.id(),
            authority,
            epoch: owner.epoch(),
            policy_revision: revision,
            topic,
            selector,
        };
        let automatic = peer.is_none();
        let mut candidates = match peer {
            Some(peer) => vec![peer],
            None => session
                .runtime
                .block_on(session.node.live_neighbors(query.workspace)),
        };
        if automatic {
            candidates.sort_unstable();
            candidates.dedup();
            candidates.truncate(MAX_WORKSPACE_OVERLAY_PATHS);
            if authority_endpoint != session.node.id()
                && !candidates.contains(&authority_endpoint)
                && (session.node.can_dial_by_peer_id()
                    || session
                        .runtime
                        .block_on(session.node.address_hint(authority_endpoint))
                        .is_some())
            {
                candidates.insert(0, authority_endpoint);
            }
            candidates.retain(|candidate| {
                check_recovery_policy(
                    session,
                    *candidate,
                    authority,
                    query.workspace,
                    query.epoch,
                    revision,
                    &topics,
                )
                .is_ok()
            });
        } else {
            check_recovery_policy(
                session,
                candidates[0],
                authority,
                query.workspace,
                query.epoch,
                revision,
                &topics,
            )?;
        }
        if candidates.is_empty() {
            return Ok(json!({"state":"current_view_source_waiting", "accepted_progress":false}));
        }
        let wire = query.to_wire().map_err(str::to_owned)?;
        let requests = candidates
            .iter()
            .map(|peer| (*peer, session.node.request_control(*peer, &wire)))
            .collect::<Vec<_>>();
        let candidate_count = requests.len();
        let (reply_tx, replies) = mpsc::channel(candidate_count);
        let task = session.runtime.spawn(async move {
            let mut pending = tokio::task::JoinSet::new();
            for (peer, request) in requests {
                pending.spawn(async move { (peer, request.await.map_err(|e| e.to_string())) });
            }
            while let Some(result) = pending.join_next().await {
                if let Ok(reply) = result
                    && reply_tx.send(reply).await.is_err()
                {
                    break;
                }
            }
        });
        session.current_view = Some(PendingCurrentView {
            query,
            automatic,
            replies,
            task,
            attempted: 0,
            reason: None,
            best: None,
        });
        json!({"state":"current_view_pending", "candidate_count":candidate_count,
            "automatic_source":automatic, "accepted_progress":false})
    } else if matches!(request, Request::PollCurrentView {}) {
        let Some(mut active) = session.current_view.take() else {
            return Ok(Value::Null);
        };
        let query = active.query.clone();
        let automatic = active.automatic;
        let topics = BTreeSet::from([query.topic.clone()]);
        loop {
            match active.replies.try_recv() {
                Ok((peer, reply)) => {
                    active.attempted += 1;
                    let result = check_recovery_policy(
                        session,
                        peer,
                        query.authority,
                        query.workspace,
                        query.epoch,
                        query.policy_revision,
                        &topics,
                    )
                    .and_then(|_| reply.map_err(|_| "reachable holder did not answer".into()))
                    .and_then(|reply| {
                        let owner = session
                            .workspace
                            .as_ref()
                            .ok_or("session has no workspace")?;
                        arachne_delivery::current::verify_wire_reply(owner, &query, &reply)
                            .map_err(|_| "holder returned invalid current-view evidence".into())
                            .and_then(|view| {
                                view.map(|view| (reply, view))
                                    .ok_or("holder has no current view".into())
                            })
                    });
                    match result {
                        Ok((reply, view)) => {
                            let candidate = ReadyCurrentView {
                                query: query.clone(),
                                peer,
                                cut: view.cut,
                                value_count: view.values.len(),
                                reply,
                            };
                            if active.best.as_ref().is_none_or(|best| {
                                (candidate.cut, &candidate.reply) > (best.cut, &best.reply)
                            }) {
                                active.best = Some(candidate);
                            }
                        }
                        Err(reason) => active.reason = Some(reason),
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) if !active.task.is_finished() => {
                    session.current_view = Some(active);
                    return Ok(Value::Null);
                }
                Err(_) => break,
            }
        }
        let attempted = active.attempted;
        if let Some(ready) = active.best.take() {
            let cut = ready.cut;
            let value_count = ready.value_count;
            session.ready_current_view = Some(ready);
            json!({"state":"current_view_ready", "cut":cut,
                "value_count":value_count, "automatic_source":automatic,
                "attempted":attempted, "accepted_progress":false})
        } else if automatic {
            json!({"state":"current_view_unavailable", "attempted":attempted,
                "reason":active.reason.take().unwrap_or_else(|| "no current holder supplied an authenticated view".into()),
                "automatic_source":true, "accepted_progress":false})
        } else if active.reason.as_deref() == Some("holder has no current view") {
            json!({"state":"current_view_unavailable", "reason":active.reason.take().unwrap(),
                "automatic_source":false, "accepted_progress":false})
        } else {
            return Err(active
                .reason
                .take()
                .unwrap_or_else(|| "current-view request failed".into()));
        }
    } else if matches!(request, Request::StageCurrentView {}) {
        let (query, peer, reply, cut) = {
            let ready = session
                .ready_current_view
                .as_ref()
                .ok_or("no current view ready")?;
            (
                ready.query.clone(),
                ready.peer,
                ready.reply.clone(),
                ready.cut,
            )
        };
        let topics = BTreeSet::from([query.topic.clone()]);
        check_recovery_policy(
            session,
            peer,
            query.authority,
            query.workspace,
            query.epoch,
            query.policy_revision,
            &topics,
        )?;
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        let key = session
            .storage_key
            .as_ref()
            .ok_or("session has no protected root key")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch")?
            .as_secs();
        let (mut inbox, pending, stale) = session
            .inbox
            .as_ref()
            .ok_or("object delivery not enabled")?
            .accept_current_view(owner, &query, &reply, now)
            .map_err(str::to_owned)?;
        if arachne_delivery::current::verify_wire_reply(owner, &query, &reply)
            .map_err(str::to_owned)?
            .is_some_and(|view| view.values.iter().any(|value| value.expires_at > now))
        {
            inbox = inbox
                .retain_current_view(owner, &query, &reply, now)
                .map_err(str::to_owned)?;
        }
        let publisher = session
            .publisher
            .clone()
            .unwrap_or(arachne_delivery::PublisherLog::new(
                owner.id(),
                owner.member().ok_or("member required")?.id(),
                owner.epoch(),
            ));
        let snapshot = seal_state(
            session.records.is_some(),
            owner,
            key,
            Some(&publisher),
            session.received.as_ref(),
            Some(&inbox),
        )?;
        let candidate = owner.provisional_copy().map_err(str::to_owned)?;
        session.staged_workspace = Some(StagedWorkspace {
            publisher: Some(publisher),
            received: session.received.clone(),
            inbox: Some(inbox),
            transition: WorkspaceTransition::CurrentView {
                cut,
                pending,
                stale,
            },
            workspace: candidate,
            snapshot: snapshot.clone(),
        });
        session.ready_current_view = None;
        json!({"workspace":owner.id(), "snapshot":snapshot,
            "state":"awaiting_current_view_save", "cut":cut,
            "pending":pending, "stale":stale, "durable":false,
            "accepted_progress":false})
    } else if matches!(request, Request::CancelCurrentView {}) {
        drop(session.current_view.take());
        session.ready_current_view = None;
        json!({"state":"current_view_cancelled", "accepted_progress":false})
    } else if let Request::DiscoverRecoveryCutoff {
        peer,
        revision,
        topics,
    } = request
    {
        if session.cutoff.is_some()
            || session.range.is_some()
            || session.ready_range.is_some()
            || session.direct_range.is_some()
            || session.ready_direct_range.is_some()
            || session.current_view.is_some()
            || session.ready_current_view.is_some()
        {
            return Err("recovery operation already pending".into());
        }
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        if peer == session.node.id()
            || topics.is_empty()
            || topics.len() > arachne_delivery::MAX_TOPICS
        {
            return Err("invalid recovery peer or selection".into());
        }
        let count = topics.len();
        let topics = topics
            .into_iter()
            .map(Topic::new)
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|e| e.to_string())?;
        if topics.len() != count {
            return Err("duplicate recovery topic".into());
        }
        let expected = owner
            .recovery_cutoff_request(peer, arachne_delivery::selection_digest(&topics), revision)
            .map_err(str::to_owned)?;
        let query = arachne_delivery::wire::CutoffQuery {
            workspace: expected.workspace,
            author: expected.author,
            epoch: expected.epoch,
            policy_revision: revision,
            topics,
            nonce: expected.nonce,
        };
        check_recovery_policy(
            session,
            peer,
            query.author,
            query.workspace,
            query.epoch,
            query.policy_revision,
            &query.topics,
        )?;
        let task = session.runtime.spawn(
            session
                .node
                .request_control(peer, &query.to_wire().map_err(str::to_owned)?),
        );
        session.cutoff = Some(PendingControl { query, peer, task });
        json!({"state":"recovery_cutoff_pending", "accepted_progress":false})
    } else if matches!(request, Request::PollRecoveryCutoff {}) {
        if !session
            .cutoff
            .as_ref()
            .is_some_and(|pending| pending.task.is_finished())
        {
            return Ok(Value::Null);
        }
        // Consume once, including errors. No session lock was held by the task.
        let mut pending = session.cutoff.take().unwrap();
        check_recovery_policy(
            session,
            pending.peer,
            pending.query.author,
            pending.query.workspace,
            pending.query.epoch,
            pending.query.policy_revision,
            &pending.query.topics,
        )?;
        let reply = session
            .runtime
            .block_on(&mut pending.task)
            .map_err(|_| "recovery cutoff task cancelled")?
            .map_err(|e| e.to_string())?;
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        let head = if reply == arachne_delivery::wire::denied_reply() {
            None
        } else {
            Some(
                owner
                    .verify_recovery_window(
                        &pending.query.request().map_err(str::to_owned)?,
                        &reply,
                    )
                    .map_err(str::to_owned)?,
            )
        };
        let query = &pending.query;
        match head {
            Some((after, head)) => {
                let accepted_through = session
                    .inbox
                    .as_ref()
                    .map_or_else(
                        || {
                            session
                                .received
                                .as_ref()
                                .and_then(|received| received.progress(query.author, &query.topics))
                        },
                        |inbox| Some(inbox.recovery_progress(query.author, &query.topics)),
                    )
                    .unwrap_or(0);
                json!({"state":"recovery_cutoff_observed", "workspace":owner.id(),
                "author":query.author, "peer":pending.peer, "epoch":owner.epoch(), "revision":query.policy_revision,
                "topics":query.topics.iter().map(|t|t.as_str()).collect::<Vec<_>>(),
                "head":head, "retained_after":after, "accepted_through":accepted_through,
                "accepted_progress":false})
            }
            None => json!({"state":"recovery_cutoff_denied", "accepted_progress":false}),
        }
    } else if let Request::FetchInvitationCheckpoint {
        peer,
        mut peers,
        invitation,
    } = request
    {
        if let Some(peer) = peer {
            peers.insert(0, peer);
        }
        return session.runtime.block_on(request_invitation_checkpoint(
            session.node.control_client(),
            session.node.id(),
            invitation,
            peers,
        ));
    } else if let Request::JoinViaPeer { peer } = request {
        let pending = session
            .pending_join
            .as_ref()
            .ok_or("session has no pending join")?;
        let request = pending.admission_request().map_err(str::to_owned)?;
        let name = pending.member().display_name().as_bytes();
        let mut packet = b"DFJA\x02".to_vec();
        packet.extend((request.len() as u32).to_be_bytes());
        packet.extend((name.len() as u16).to_be_bytes());
        packet.extend(request);
        packet.extend(name);
        packet.extend(pending.admission_checkpoint().map_err(str::to_owned)?);
        let outcome = session
            .runtime
            .block_on(session.node.request_control(peer, &packet));
        let reply = match outcome {
            Ok(reply) => reply,
            Err(arachne_node::Error::ControlNotSent(_) | arachne_node::Error::MissingPeer) => {
                return Ok(json!({"state":"admission_not_sent","peer":peer}));
            }
            // Sent, outcome unknown. If the owner is gone, the next ask fails at
            // connect, reports `admission_not_sent`, and takes the backoff path.
            Err(arachne_node::Error::Timeout(_) | arachne_node::Error::Transport(_)) => {
                return Ok(json!({"state":admission_state::WAITING,"peer":peer}));
            }
            Err(error) => return Err(error.to_string()),
        };
        // Every accepted page's wire size, so the caller can prove the
        // responder stayed inside the control-reply bound while rolling a long
        // history over many pages.
        let mut page_bytes = vec![reply.len()];
        let mut reply: Value =
            serde_json::from_slice(&reply).map_err(|_| "invalid admission reply")?;
        if reply
            .get("history_complete")
            .is_some_and(|complete| !complete.as_bool().unwrap_or(false))
        {
            let mut commits = reply["commits"]
                .as_array()
                .cloned()
                .ok_or("admission history page missing commits")?;
            let mut offset = reply["history_next"]
                .as_u64()
                .ok_or("admission history page missing next offset")?
                as usize;
            let mut page_count = 0;
            // A responder is a reachable member, not a trusted one. Bound the
            // whole exchange, not just each page: pages, steps and total bytes
            // held for this pending join all fail closed, so a faulty or
            // hostile member cannot grow this session one small page at a time.
            let mut total_bytes: usize = page_bytes.iter().sum();
            while !reply["history_complete"].as_bool().unwrap_or(false) {
                page_count += 1;
                // Rollover means more pages, never a bigger page: a page still
                // carries at most a chunk, so the page budget is the total step
                // budget rather than a separate constant.
                if page_count > arachne_security::MAX_JOIN_HISTORY_STEPS {
                    return Err("admission history page count exceeds bounds".into());
                }
                let page = admission_history_page_packet(
                    request,
                    pending.admission_checkpoint().map_err(str::to_owned)?,
                    offset,
                )?;
                let page = session
                    .runtime
                    .block_on(session.node.request_control(peer, &page))
                    .map_err(|error| error.to_string())?;
                total_bytes = total_bytes.saturating_add(page.len());
                if total_bytes > arachne_security::MAX_JOIN_HISTORY_BYTES {
                    return Err("admission history exceeds transport bounds".into());
                }
                page_bytes.push(page.len());
                let page: Value =
                    serde_json::from_slice(&page).map_err(|_| "invalid admission history page")?;
                // A served page carries the retained reply plus its paging
                // markers; only a refusal carries a `state`. Requiring both was
                // unreachable, and no branch short enough to fit one page ever
                // reached this loop to show it.
                if page.get("history_page").and_then(Value::as_bool) != Some(true) {
                    return Err("admission history page was not accepted".into());
                }
                if page["history_offset"].as_u64() != Some(offset as u64) {
                    return Err("admission history page offset mismatch".into());
                }
                let page_commits = page["commits"]
                    .as_array()
                    .ok_or("admission history page missing commits")?;
                let next = page["history_next"]
                    .as_u64()
                    .ok_or("admission history page missing next offset")?
                    as usize;
                if page_commits.is_empty() || next <= offset {
                    return Err("admission history page made no progress".into());
                }
                if commits.len() + page_commits.len() > arachne_security::MAX_JOIN_HISTORY_STEPS {
                    return Err("admission history exceeds step bounds".into());
                }
                commits.extend(page_commits.iter().cloned());
                offset = next;
                reply = page;
            }
            reply["commits"] = Value::Array(commits);
            reply["history_complete"] = Value::Bool(true);
        }
        // Roll the fetched history over at the same chunk boundary the inline
        // encoding uses. The host still carries at most one chunk into its
        // StageJoin call; the rest stays here and is replayed -- never trusted
        // -- when the join is staged.
        let total = reply["commits"].as_array().map_or(0, Vec::len);
        if total > arachne_security::HISTORY_CHUNK_STEPS {
            let trailing = match total % arachne_security::HISTORY_CHUNK_STEPS {
                0 => arachne_security::HISTORY_CHUNK_STEPS,
                remainder => remainder,
            };
            let split = total - trailing;
            let commits = reply["commits"].as_array().unwrap();
            let prefix = commits[..split].to_vec();
            let carried = Value::Array(commits[split..].to_vec());
            reply["commits"] = carried;
            reply["history_verified_prefix"] = json!(split);
            session.join_history_prefix = prefix;
        } else {
            session.join_history_prefix.clear();
        }
        if reply.get("commits").is_some() {
            // Only a reply that actually served history reports page sizes; a
            // queued or refused attempt keeps its exact previous shape.
            reply["history_page_bytes"] = json!(page_bytes);
        }
        reply
    } else if let Request::ListAdmissionApprovals { after, limit } = request {
        list_pending_approvals(session, after, limit)?
    } else if let Request::AcknowledgeAdmissionApproval { attempt_id } = request {
        let pending = session
            .pending_approvals
            .get_mut(&attempt_id)
            .ok_or("admission approval is no longer pending")?;
        pending.acknowledged = true;
        json!({"state":admission_state::APPROVAL_PENDING,"attempt_id":attempt_id,"acknowledged":true})
    } else if let Request::PollAdmission { profile } = request {
        reap_admission_pushes(session);
        // A range pull is a short read of committed steps. Serve it before
        // the rest of the queue: behind a join wave's profile-page queries it
        // waited past the puller's limit (tablets, fix16; ADR 0009).
        if let Some(incoming) = session
            .node
            .poll_control_first(|payload| payload.starts_with(b"DFMS"), RANGE_SCAN_DEPTH)
        {
            let waited_ms = incoming.waited().as_millis() as u64;
            let reply = membership::range_reply(
                session.workspace.as_deref(),
                incoming.peer(),
                incoming.payload(),
            );
            tracing::info!(target: "data_fabric_transport", waited_ms, "RANGE_REQUEST_SERVED");
            let _ = incoming.respond(reply);
            return Ok(json!({"state":"membership_replied", "remote_receipt":false}));
        }
        // Names that membership queries retained without the host go on by
        // gossip here; the answer never waited for them.
        membership::send_queued_profiles(session);
        let admission_busy = admission_busy(session);
        // A membership step received by gossip moves this member to the next
        // epoch before anything else is staged (ADR 0008).
        if !admission_busy && let Some(staged) = membership::stage_gossiped_step(session)? {
            return Ok(staged);
        }
        // Stage on a count trigger (queue depth or reads since the last
        // attempt) independent of whether the inbox is empty this poll.
        // Continuous admission intake can keep an incoming packet available on
        // every poll, and waiting for "no incoming" then starves staging.
        if !admission_busy
            && should_stage_queued_admission(session)
            && let Some(staged) = stage_queued_admission(session)?
        {
            return Ok(staged);
        }
        // Drain an already-arrived admission retry before staging another
        // membership transition. The owner has one durable candidate slot.
        let incoming = if admission_busy || !session.admission_queue.is_empty() {
            session
                .node
                .poll_control_matching(admission_packet_candidate)
        } else {
            session.node.poll_control()
        };
        if incoming.is_none()
            && !admission_busy
            && let Some(staged) = stage_queued_admission(session)?
        {
            return Ok(staged);
        }
        let incoming = incoming.or_else(|| {
            if admission_busy {
                None
            } else {
                session.node.poll_control()
            }
        });
        let Some(incoming) = incoming else {
            // Membership queries the committed view answered: tell the host
            // once, when it has nothing else to do (ADR 0010).
            return Ok(membership::take_answered(session).unwrap_or(Value::Null));
        };
        if incoming.payload() == NEARBY_IDENTITY {
            incoming
                .respond(
                    session
                        .nearby_identity
                        .as_deref()
                        .unwrap_or("Unnamed Arachne device")
                        .as_bytes()
                        .to_vec(),
                )
                .map_err(|error| error.to_string())?;
            return Ok(json!({"state":"nearby_identity_replied"}));
        }
        if incoming.payload() == NEARBY_WORKSPACE {
            incoming
                .respond(nearby_workspace_reply(&session.nearby_workspaces))
                .map_err(|error| error.to_string())?;
            return Ok(json!({"state":"nearby_workspace_replied"}));
        }
        if incoming.payload().starts_with(NEARBY_INVITATION) {
            let payload = incoming.payload();
            if payload.len() < 7 {
                let _ = incoming.respond(vec![0]);
                return Ok(json!({"state":"nearby_invitation_rejected"}));
            }
            let length = u16::from_be_bytes(payload[5..7].try_into().unwrap()) as usize;
            if length == 0 || length > 2048 || payload.len() != 7 + length {
                let _ = incoming.respond(vec![0]);
                return Ok(json!({"state":"nearby_invitation_rejected"}));
            }
            let peer = incoming.peer();
            let invitation = payload[7..].to_vec();
            incoming
                .respond(vec![1])
                .map_err(|error| error.to_string())?;
            return Ok(
                json!({"state":"nearby_invitation_received","peer":peer,"invitation":invitation}),
            );
        }
        if incoming.payload().starts_with(b"DFPR") {
            let peer = incoming.peer();
            let result = presence::receive(session, peer, incoming.payload());
            if result.is_ok()
                && let Some(address) = incoming.remote_address()
            {
                session
                    .runtime
                    .block_on(session.node.remember_observed(peer, address));
            }
            let accepted = result.is_ok();
            let _ = incoming.respond(result.unwrap_or_else(|_| vec![0]));
            return Ok(json!({"state":"presence_replied","accepted":accepted}));
        }
        if incoming.payload().starts_with(b"DFLV") {
            let value =
                match membership::receive_leave(session, incoming.peer(), incoming.payload()) {
                    Ok(value) => value,
                    Err(_) => {
                        let _ = incoming.respond(b"{\"state\":\"leave_denied\"}".to_vec());
                        return Ok(json!({"state":"membership_replied"}));
                    }
                };
            session.inbound_admission = Some(incoming);
            return Ok(value);
        }
        if incoming.payload().starts_with(b"DFMO") {
            let offered = membership::receive_offer(session, incoming.payload());
            return match offered {
                Ok(value) => {
                    session.inbound_admission = Some(incoming);
                    Ok(value)
                }
                Err(_) => {
                    let _ = incoming.respond(vec![0]);
                    Ok(json!({"state":"membership_replied"}))
                }
            };
        }
        if incoming
            .payload()
            .starts_with(INVITATION_CHECKPOINT_REQUEST)
        {
            let reply = invitation_checkpoint_reply(session, incoming.peer(), incoming.payload());
            let accepted = reply.is_ok();
            let _ = incoming.respond(reply.unwrap_or_default());
            return Ok(json!({"state":"invitation_checkpoint_replied","accepted":accepted}));
        }
        if incoming.payload().starts_with(b"DFMS") {
            let reply = membership::range_reply(
                session.workspace.as_deref(),
                incoming.peer(),
                incoming.payload(),
            );
            let _ = incoming.respond(reply);
            return Ok(json!({"state":"membership_replied", "remote_receipt":false}));
        }
        if incoming
            .payload()
            .starts_with(membership::PROFILE_QUERY_PREFIX)
        {
            let reply = membership::profile_page_reply(
                session.workspace.as_deref(),
                &membership::lock_profiles(&session.profiles),
                incoming.peer(),
                incoming.payload(),
            );
            let _ = incoming.respond(reply);
            return Ok(json!({"state":"membership_replied", "remote_receipt":false}));
        }
        if incoming.payload().starts_with(b"DFMQ") {
            let peer = incoming.peer();
            let reply = membership::reply_with_profiles(session, peer, incoming.payload());
            let current_peer = reply["state"] != "membership_denied"
                && session
                    .workspace
                    .as_ref()
                    .is_some_and(|owner| owner.member_id_for_endpoint(peer).is_ok());
            incoming
                .respond(membership::encode_reply(&reply)?)
                .map_err(|e| e.to_string())?;
            let mut event = json!({"state":"membership_replied", "remote_receipt":false});
            if current_peer {
                event["peer"] = json!(peer);
            }
            return Ok(event);
        }
        // One control queue: route continuity before admission parsing. Never serve
        // staged state (the dispatcher rejects polls while adoption is pending).
        if incoming.payload().starts_with(b"DFRQ")
            || incoming.payload().starts_with(b"DFHQ")
            || incoming.payload().starts_with(b"DFCQ")
            || incoming.payload().starts_with(b"DFVQ")
            || incoming.payload().starts_with(b"DFDQ")
        {
            let reply = match session.workspace.as_ref() {
                Some(owner) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| "system clock is before Unix epoch")?
                        .as_secs();
                    session
                        .runtime
                        .block_on(session.node.with_routing_policy(|policy| {
                            if incoming.payload().starts_with(b"DFDQ") {
                                match (
                                    session.inbox.as_ref(),
                                    arachne_delivery::wire::DirectRangeQuery::from_wire(
                                        incoming.payload(),
                                    ),
                                ) {
                                    (Some(inbox), Ok(query)) => inbox.serve_direct_range(
                                        owner,
                                        policy,
                                        incoming.peer(),
                                        &query,
                                    ),
                                    _ => Ok(arachne_delivery::wire::unavailable_direct_reply()),
                                }
                            } else if incoming.payload().starts_with(b"DFVQ") {
                                match (
                                    session.inbox.as_ref(),
                                    arachne_delivery::current::CurrentViewQuery::from_wire(
                                        incoming.payload(),
                                    ),
                                ) {
                                    (Some(inbox), Ok(query)) => inbox.serve_current(
                                        owner,
                                        policy,
                                        incoming.peer(),
                                        &query,
                                        now,
                                    ),
                                    _ => Ok(arachne_delivery::current::CurrentView::denied_wire()),
                                }
                            } else if incoming.payload().starts_with(b"DFCQ") {
                                match (
                                    session.publisher.as_ref(),
                                    arachne_delivery::wire::CutoffQuery::from_wire(
                                        incoming.payload(),
                                    ),
                                ) {
                                    (Some(log), Ok(query)) => arachne_delivery::wire::serve_cutoff(
                                        log,
                                        owner,
                                        policy,
                                        incoming.peer(),
                                        &query,
                                    ),
                                    _ => Ok(arachne_delivery::wire::denied_reply()),
                                }
                            } else if incoming.payload().starts_with(b"DFHQ") {
                                let Ok(query) =
                                    arachne_delivery::wire::AvailableRangeQuery::from_wire(
                                        incoming.payload(),
                                    )
                                else {
                                    return Ok(
                                        arachne_delivery::wire::unavailable_available_reply(),
                                    );
                                };
                                if owner.member().map(|member| member.id()) == Some(query.author) {
                                    match session.publisher.as_ref() {
                                        Some(log) => arachne_delivery::wire::serve_available_range(
                                            log,
                                            owner,
                                            policy,
                                            incoming.peer(),
                                            &query,
                                        ),
                                        None => Ok(
                                            arachne_delivery::wire::unavailable_available_reply(),
                                        ),
                                    }
                                } else {
                                    match session.inbox.as_ref() {
                                        Some(inbox) => inbox.serve_available_range(
                                            owner,
                                            policy,
                                            incoming.peer(),
                                            &query,
                                            now,
                                        ),
                                        None => Ok(
                                            arachne_delivery::wire::unavailable_available_reply(),
                                        ),
                                    }
                                }
                            } else {
                                let Ok(query) =
                                    arachne_delivery::RangeQuery::from_wire(incoming.payload())
                                else {
                                    return Ok(arachne_delivery::wire::denied_reply());
                                };
                                if owner.member().map(|member| member.id()) == Some(query.author) {
                                    match session.publisher.as_ref() {
                                        Some(log) => arachne_delivery::wire::serve_range(
                                            log,
                                            owner,
                                            policy,
                                            incoming.peer(),
                                            &query,
                                        ),
                                        None => Ok(arachne_delivery::wire::denied_reply()),
                                    }
                                } else {
                                    match session.inbox.as_ref() {
                                        Some(inbox) => inbox.serve_range(
                                            owner,
                                            policy,
                                            incoming.peer(),
                                            &query,
                                            now,
                                        ),
                                        None => Ok(arachne_delivery::wire::denied_reply()),
                                    }
                                }
                            }
                        }))
                        .map_err(str::to_owned)?
                }
                None if incoming.payload().starts_with(b"DFVQ") => {
                    arachne_delivery::current::CurrentView::denied_wire()
                }
                None if incoming.payload().starts_with(b"DFHQ") => {
                    arachne_delivery::wire::unavailable_available_reply()
                }
                None if incoming.payload().starts_with(b"DFDQ") => {
                    arachne_delivery::wire::unavailable_direct_reply()
                }
                None => arachne_delivery::wire::denied_reply(),
            };
            let state = if incoming.payload().starts_with(b"DFVQ") {
                "current_view_replied"
            } else if incoming.payload().starts_with(b"DFDQ") {
                "direct_recovery_replied"
            } else {
                "recovery_replied"
            };
            incoming.respond(reply).map_err(|e| e.to_string())?;
            return Ok(json!({"state":state, "remote_receipt":false}));
        }
        if admission_packet_candidate(incoming.payload()) {
            let mut value = queue_admission(session, incoming)?;
            // The intake marker is measurement, not state. Only a caller that
            // asked to profile sees it, so every other caller's reply shape is
            // exactly what it was.
            if !profile && let Some(object) = value.as_object_mut() {
                object.remove("intake");
            }
            return Ok(value);
        }
        let result: Result<Value, String> = (|| {
            let workspace = session
                .workspace
                .as_ref()
                .ok_or("session has no workspace")?;
            let (request, checkpoint) = admission_parts(incoming.payload())?;
            if let Some(checkpoint) = checkpoint {
                workspace
                    .membership_history(incoming.peer(), request, checkpoint)
                    .map_err(str::to_owned)?;
            }
            let retained = workspace
                .retained_admission(incoming.peer(), request)
                .map_err(str::to_owned)?
                .is_some();
            let value = if retained {
                json!({"workspace":workspace.id(),"state":"reply_ready"})
            } else {
                stage_admission(session, incoming.peer(), request, checkpoint, None)?
            };
            Ok(value)
        })();
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                let feedback = admission_feedback(&error);
                let reason = feedback["reason"]
                    .as_str()
                    .ok_or("admission feedback has no reason")?;
                // An invalid/unapproved request is not a failure of the member's
                // accepted workspace. Reply without exposing details or stopping it.
                let approval = if reason == "approval_required"
                    || reason == "automatic_approval_required"
                {
                    let (request, _, display_name) = admission_packet(incoming.payload())?;
                    Some((
                        incoming.peer(),
                        request.to_vec(),
                        display_name.map(str::to_owned),
                    ))
                } else {
                    None
                };
                let _ = incoming.respond(
                    serde_json::to_vec(&feedback)
                        .map_err(|_| "admission feedback encoding failed")?,
                );
                if let Some((endpoint, request, display_name)) = approval {
                    return Ok(
                        json!({"state":"approval_requested","endpoint":endpoint,"request":request,"display_name":display_name,"automatic":reason == "automatic_approval_required"}),
                    );
                }
                let mut response = json!({
                    "state": admission_state::REPLIED,
                    "accepted": false,
                    "reason": reason,
                });
                if let Some(recovery) = feedback.get("recovery") {
                    response["recovery"] = recovery.clone();
                }
                return Ok(response);
            }
        };
        session.inbound_admission = Some(incoming);
        value
    } else if matches!(request, Request::SendAdmissionReply {}) {
        send_inbound_admission_reply(session)?
    } else if let Request::StageJoin { commits, welcome } = request {
        if commits.is_empty() || commits.len() > arachne_security::HISTORY_CHUNK_STEPS {
            return Err("join history exceeds step bounds".into());
        }
        let pending = session
            .pending_join
            .as_ref()
            .ok_or("session has no pending join")?;
        let key = session
            .storage_key
            .as_ref()
            .ok_or("session has no protected root key")?;
        let mut proof = pending.join_proof().map_err(str::to_owned)?;
        // Replay the rolled-over prefix from the pinned checkpoint before the
        // chunk the host carried back. Nothing is accepted on the strength of
        // having been fetched earlier: a truncated or tampered prefix fails
        // here exactly as it would on a first, unrolled verification.
        for value in &session.join_history_prefix {
            let step: JoinStep =
                serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
            proof
                .apply_transition(&step.authorization()?, &step.commit)
                .map_err(str::to_owned)?;
        }
        for step in commits {
            proof
                .apply_transition(&step.authorization()?, &step.commit)
                .map_err(str::to_owned)?;
        }
        let workspace = pending
            .prepare_workspace(&proof, &welcome)
            .map_err(str::to_owned)?;
        let snapshot = seal_state(session.records.is_some(), &workspace, key, None, None, None)?;
        let value = json!({"workspace":workspace.id(), "workspace_name":workspace.workspace_name().map_err(str::to_owned)?, "snapshot":snapshot, "state":"awaiting_join_save", "durable":false});
        session.staged_workspace = Some(StagedWorkspace {
            publisher: None,
            received: None,
            inbox: None,
            transition: WorkspaceTransition::Join,
            workspace,
            snapshot,
        });
        transition_activity(session, WorkspacePhase::Synchronizing, None)?;
        let mut value = value;
        value["activity"] = activity_value(session);
        value
    } else if let Request::MemberRoster { profiles } = request {
        membership::roster(session, &profiles)?
    } else if matches!(request, Request::UseServiceProfile {}) {
        membership::lock_profiles(&session.profiles).service = true;
        json!({"state":"service_profile"})
    } else if matches!(
        request,
        Request::StageWorkspaceName { .. }
            | Request::StageWorkspaceNameUpdate { .. }
            | Request::StageWorkspaceNameCheckpoint { .. }
    ) {
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        let (workspace, missing) = match request {
            Request::StageWorkspaceName { workspace_name } => owner
                .prepare_workspace_name(&workspace_name)
                .map(|p| (p.workspace, None)),
            Request::StageWorkspaceNameUpdate { name_record } => owner
                .prepare_workspace_name_update(&name_record)
                .map(|workspace| (workspace, None)),
            Request::StageWorkspaceNameCheckpoint { name_checkpoint } => owner
                .prepare_workspace_name_checkpoint(&name_checkpoint)
                .map(|prepared| (prepared.workspace, Some(prepared.missing))),
            _ => unreachable!(),
        }
        .map_err(str::to_owned)?;
        let snapshot = seal_state(
            session.records.is_some(),
            &workspace,
            session
                .storage_key
                .as_ref()
                .ok_or("session has no protected root key")?,
            session.publisher.as_ref(),
            session.received.as_ref(),
            session.inbox.as_ref(),
        )?;
        let mut value = json!({"workspace":workspace.id(),"workspace_name":workspace.workspace_name().map_err(str::to_owned)?,
            "snapshot":snapshot,"state":"awaiting_save","durable":false});
        if let Some(missing) = missing {
            value["name_history_missing_added"] = json!(missing);
            value["name_history_missing"] = json!(
                workspace
                    .workspace_name_missing_history()
                    .map_err(str::to_owned)?
            );
        }
        session.staged_workspace = Some(StagedWorkspace {
            publisher: session.publisher.clone(),
            received: session.received.clone(),
            inbox: session.inbox.clone(),
            transition: WorkspaceTransition::WorkspaceName,
            workspace,
            snapshot,
        });
        value
    } else if let Request::StageInvitation {
        expires_at,
        personal,
        automatic,
        request_access,
    } = request
    {
        check_epoch_transition(session)?;
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        if request_access && (!personal || automatic) {
            return Err("invalid request-access mode".into());
        }
        let (prepared, invitation, checkpoint) = if request_access {
            owner.prepare_request_invitation(expires_at)
        } else {
            owner.prepare_invitation(expires_at, personal, automatic)
        }
        .map_err(str::to_owned)?;
        let action = prepared.action;
        let commit = prepared.commit.clone();
        let value = membership::stage_prepared(session, prepared)?;
        session.staged_workspace.as_mut().unwrap().transition =
            WorkspaceTransition::Invitation(Box::new(invitation), checkpoint, action, commit);
        value
    } else if let Request::StageInvitationApproval {
        request,
        attempt_id,
    } = request
    {
        check_epoch_transition(session)?;
        let pending_id = pending_approval_id(session, &request, attempt_id)?;
        let prepared = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?
            .prepare_invitation_approval(&request)
            .map_err(str::to_owned)?;
        let value = membership::stage_prepared(session, prepared)?;
        session.staged_approval_id = pending_id;
        value
    } else if let Request::StageInvitationDecline {
        request,
        attempt_id,
    } = request
    {
        check_epoch_transition(session)?;
        let pending_id = pending_approval_id(session, &request, attempt_id)?;
        let prepared = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?
            .prepare_invitation_decline(&request)
            .map_err(str::to_owned)?;
        let value = membership::stage_prepared(session, prepared)?;
        session.staged_approval_id = pending_id;
        value
    } else if matches!(request, Request::InvitationControls {}) {
        let owner = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        let (legacy, controls) = owner.invitation_controls().map_err(str::to_owned)?;
        json!({"legacy_enabled":legacy,"invitations":controls.iter().filter(|c| !c.is_request_decision(&controls)).enumerate().map(|(i,c)| json!({"number":i+1,"key":c.key,"expires_at":c.expires_at,"enabled":c.enabled,"personal":c.personal,"automatic":c.automatic(),"request_access":c.request_access(),"approved":c.approved()})).collect::<Vec<_>>()})
    } else if let Request::StageManagement { action } = request {
        membership::stage_management(session, action.action()?)?
    } else if let Request::LeaveViaPeer { peer } = request {
        membership::leave_via_peer(session, peer)?
    } else if matches!(request, Request::StageSoloLeave {}) {
        check_epoch_transition(session)?;
        let ended = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?
            .prepare_solo_leave()
            .map_err(str::to_owned)?;
        membership::stage_removal(session, ended)?
    } else if let Request::StageAdmissionUpdate { step } = request {
        membership::stage_update(session, step)?
    } else if let Request::StageAdmission {
        authenticated_endpoint,
        request,
    } = request
    {
        stage_admission(session, authenticated_endpoint, &request, None, None)?
    } else if matches!(
        request,
        Request::AdoptAdmission { .. }
            | Request::AdoptJoin { .. }
            | Request::AdoptPublication { .. }
            | Request::AdoptReception { .. }
            | Request::AdoptRecovery { .. }
            | Request::AdoptCurrentView { .. }
    ) {
        let staged = session
            .staged_workspace
            .as_ref()
            .ok_or("session has no workspace candidate")?;
        let valid_phase = matches!(
            (&request, &staged.transition),
            (
                Request::AdoptAdmission { .. },
                WorkspaceTransition::Admission
                    | WorkspaceTransition::Management(_, _)
                    | WorkspaceTransition::WorkspaceName
                    | WorkspaceTransition::Invitation(..)
            ) | (Request::AdoptJoin { .. }, WorkspaceTransition::Join)
                | (
                    Request::AdoptRecovery { .. },
                    WorkspaceTransition::Recovery(_)
                        | WorkspaceTransition::InboxRecovery { .. }
                        | WorkspaceTransition::DirectMiss { .. }
                )
                | (
                    Request::AdoptCurrentView { .. },
                    WorkspaceTransition::CurrentView { .. }
                )
                | (
                    Request::AdoptPublication { .. },
                    WorkspaceTransition::Publication(_)
                        | WorkspaceTransition::RoutedPublication(..)
                )
                | (
                    Request::AdoptReception { .. },
                    WorkspaceTransition::Reception(_)
                        | WorkspaceTransition::RoutedReception(..)
                        | WorkspaceTransition::Inbox
                        | WorkspaceTransition::InboxRejected
                )
        );
        if !valid_phase {
            return Err("wrong adoption lifecycle phase".into());
        }
        let snapshot = match request {
            Request::AdoptAdmission { snapshot }
            | Request::AdoptJoin { snapshot }
            | Request::AdoptPublication { snapshot }
            | Request::AdoptReception { snapshot }
            | Request::AdoptRecovery { snapshot }
            | Request::AdoptCurrentView { snapshot } => snapshot,
            _ => unreachable!(),
        };
        if snapshot != staged.snapshot {
            return Err("workspace snapshot does not match candidate".into());
        }
        if let Some(store) = &session.records {
            store.require_committed(&snapshot)?;
        }
        let staged = session.staged_workspace.take().unwrap();
        let joined = matches!(&staged.transition, WorkspaceTransition::Join);
        let mut value = json!({"workspace":staged.workspace.id(), "workspace_name":staged.workspace.workspace_name().map_err(str::to_owned)?, "epoch":staged.workspace.epoch(),
            "workspace_name_missing_history":staged.workspace.workspace_name_missing_history().map_err(str::to_owned)?,
            "members":staged.workspace.member_count(), "durable":session.records.is_some()});
        session.publisher = staged.publisher;
        session.received = staged.received;
        session.inbox = staged.inbox;
        if matches!(&staged.transition, WorkspaceTransition::Join) {
            transition_activity(session, WorkspacePhase::Synchronizing, None)?;
        }
        commit_workspace(session, staged.workspace);
        let staged_approval_id = session.staged_approval_id;
        // A step this node committed goes out by gossip (ADR 0008). A step it
        // received from a peer is already travelling; gossip relays it.
        let received = std::mem::take(&mut session.staged_step_received);
        let committed_here =
            matches!(staged.transition, WorkspaceTransition::Admission) && !received;
        match staged.transition {
            WorkspaceTransition::Inbox => value["state"] = json!("inbox_adopted"),
            WorkspaceTransition::InboxRejected => value["state"] = json!("inbox_rejection_adopted"),
            WorkspaceTransition::InboxRecovery { count } => {
                value["state"] = json!("recovery_adopted");
                value["publication_count"] = json!(count);
            }
            WorkspaceTransition::DirectMiss { missing } => {
                value["state"] = json!("direct_miss_adopted");
                value["missing_count"] = json!(missing);
            }
            WorkspaceTransition::CurrentView {
                cut,
                pending,
                stale,
            } => {
                value["state"] = json!("current_view_adopted");
                value["cut"] = json!(cut);
                value["pending"] = json!(pending);
                value["stale"] = json!(stale);
            }
            WorkspaceTransition::Recovery(publications) => {
                value["state"] = json!("recovery_adopted");
                value["publication_count"] = json!(publications.len());
                // ponytail: bounded volatile handoff; a durable application outbox
                // is required before claiming delivery across save/callback crashes.
                session.recovered = publications.into();
            }
            WorkspaceTransition::RoutedPublication(
                context,
                delivery,
                packet,
                endpoints,
                recipients,
            ) => {
                // Adoption is final even if network admission fails or times out.
                let sent = session.runtime.block_on(async {
                    tokio::time::timeout(Duration::from_secs(10), async {
                        if recipients.is_empty() {
                            session
                                .node
                                .publish_with_class(
                                    context.workspace,
                                    context.revision,
                                    context.topic,
                                    delivery,
                                    packet,
                                )
                                .await
                        } else {
                            session
                                .node
                                .publish_to_with_class(
                                    context.workspace,
                                    context.revision,
                                    context.topic,
                                    endpoints,
                                    recipients.clone(),
                                    delivery,
                                    packet,
                                )
                                .await
                        }
                    })
                    .await
                });
                value["id"] = json!(context.id);
                value["sequence"] = json!(context.sequence.map(|n| n.get()));
                if !recipients.is_empty() {
                    value["recipients"] = json!(recipients);
                }
                match sent {
                    Ok(Ok(result)) => value["admission"] = report(result),
                    Ok(Err(error)) => value["network_error"] = json!(error.to_string()),
                    Err(_) => {
                        value["network_error"] =
                            json!("publication deadline exceeded; outcome may be partial")
                    }
                }
            }
            WorkspaceTransition::RoutedReception(context, message, recipients) => {
                value["revision"] = json!(context.revision);
                value["topic"] = json!(context.topic.as_str());
                value["id"] = json!(context.id);
                value["sequence"] = json!(context.sequence.map(|n| n.get()));
                value["payload"] = json!(message.payload);
                value["member"] = json!(message.member);
                value["endpoint"] = json!(message.endpoint);
                if !recipients.is_empty() {
                    value["recipients"] = json!(recipients);
                }
            }
            WorkspaceTransition::Management(action, commit) => {
                value["step"] = membership::step_json(
                    &arachne_security::MembershipAuthorization::Management(action),
                    &commit,
                );
            }
            WorkspaceTransition::Invitation(invitation, checkpoint, action, commit) => {
                value["issued_invitation"] = invitation_envelope(session, &invitation, checkpoint)?;
                let mut step = membership::step_json(
                    &arachne_security::MembershipAuthorization::Management(action),
                    &commit,
                );
                step["invitation_checkpoint"] = json!({
                    "grant": invitation.public_grant(),
                    "checkpoint": value["issued_invitation"]["checkpoint"],
                });
                value["step"] = step;
            }
            WorkspaceTransition::Admission => {
                let admitted = std::mem::take(&mut session.queued_admission_in_flight);
                let mut delivered = 0usize;
                let mut pushed = 0usize;
                if let Some(workspace) = session.workspace.clone() {
                    for attempt in &admitted {
                        let held = session.admission_waiters.take(&attempt.id());
                        let checkpoint = held.as_ref().and_then(|(_, checkpoint)| checkpoint.as_deref());
                        let Ok(reply) = admission_reply_page(
                            &workspace,
                            attempt.endpoint(),
                            attempt.request(),
                            checkpoint,
                            0,
                        ) else {
                            continue;
                        };
                        let (delivered_here, route) = match held {
                            Some((exchange, _)) => {
                                let route = exchange.remote_address();
                                let delivered = !exchange.expired()
                                    && exchange.respond(reply.clone()).is_ok();
                                (delivered, route)
                            }
                            None => (false, None),
                        };
                        if delivered_here {
                            delivered += 1;
                        } else if queue_admission_push(session, attempt, &reply, route) {
                            pushed += 1;
                        }
                    }
                }
                value["results_delivered"] = json!(delivered);
                value["results_pushed"] = json!(pushed);
            }
            WorkspaceTransition::WorkspaceName => {}
            WorkspaceTransition::Join => {
                session.pending_join = None;
                session.join_lifecycle = None;
                session.join_history_prefix.clear();
                transition_activity(session, WorkspacePhase::Active, None)?;
            }
            WorkspaceTransition::Publication(ciphertext) => value["ciphertext"] = json!(ciphertext),
            WorkspaceTransition::Reception(message) => {
                value["payload"] = json!(message.payload);
                value["member"] = json!(message.member);
                value["endpoint"] = json!(message.endpoint);
            }
        }
        if joined && session.inbound_admission.is_some() {
            let reply = send_inbound_admission_reply(session)?;
            value["reply_queued"] = json!(reply["queued"]);
        }
        if let Some(id) = staged_approval_id {
            session.pending_approvals.remove(&id);
            session.staged_approval_id = None;
        }
        // A member that just reached the newest head it heard announces it
        // too, so members that are behind pull from many members (ADR 0009).
        let reached_head = received
            && session.workspace.as_ref().is_some_and(|owner| {
                !session.gossip_steps_ahead.contains_key(&owner.epoch())
                    && session
                        .membership_head
                        .as_ref()
                        .is_none_or(|(head, _)| *head <= owner.epoch())
            });
        if committed_here || reached_head {
            membership::announce_head(session);
        }
        value["activity"] = activity_value(session);
        value
    } else if let Request::RetainedAdmission {
        authenticated_endpoint,
        request,
    } = request
    {
        let workspace = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        retained_reply(workspace, authenticated_endpoint, &request)?
    } else if matches!(request, Request::IssueInvitation {}) {
        let workspace = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        let (invitation, checkpoint) = workspace.issue_invitation().map_err(str::to_owned)?;
        invitation_envelope(session, &invitation, checkpoint)?
    } else if let Request::InspectInvitation {
        invitation,
        checkpoint,
    } = request
    {
        inspected_invitation(&invitation, &checkpoint)?
    } else if let Request::BeginJoin {
        invitation,
        checkpoint,
        display_name,
        peers,
    } = request
    {
        if session.workspace.is_some() || session.pending_join.is_some() {
            return Err("session already owns workspace state".into());
        }
        let invitation =
            arachne_security::Invitation::from_bytes(&invitation).map_err(str::to_owned)?;
        let pending = if checkpoint.is_empty() {
            arachne_security::PendingJoin::from_compact_invitation(
                &invitation,
                session.node.id(),
                &display_name,
            )
        } else {
            arachne_security::PendingJoin::from_invitation(
                &invitation,
                &checkpoint,
                session.node.id(),
                &display_name,
            )
        }
        .map_err(str::to_owned)?;
        transition_activity(session, WorkspacePhase::Joining, None)?;
        let value = pending_metadata(&pending, session.node.id())?;
        let mut value = value;
        value["activity"] = activity_value(session);
        session.pending_join = Some(pending);
        session.join_lifecycle = if peers.is_empty() {
            None
        } else {
            Some(JoinLifecycle::new(peers)?)
        };
        session.join_history_prefix.clear();
        value
    } else if matches!(request, Request::SealPendingJoin {}) {
        let pending = session
            .pending_join
            .as_ref()
            .ok_or("session has no pending join")?;
        let key = session
            .storage_key
            .as_ref()
            .ok_or("session has no protected root key")?;
        json!({"workspace": pending.workspace_id(), "snapshot": pending.seal(key).map_err(str::to_owned)?})
    } else if let Request::RestorePendingJoin {
        workspace,
        snapshot,
    } = request
    {
        if session.workspace.is_some() || session.pending_join.is_some() {
            return Err("session already owns workspace state".into());
        }
        let key = session
            .storage_key
            .as_ref()
            .ok_or("session has no protected root key")?;
        let pending =
            arachne_security::PendingJoin::restore(key, session.node.id(), workspace, &snapshot)
                .map_err(str::to_owned)?;
        let value = pending_metadata(&pending, session.node.id())?;
        transition_activity(session, WorkspacePhase::Joining, None)?;
        let mut value = value;
        value["activity"] = activity_value(session);
        session.pending_join = Some(pending);
        session.join_lifecycle = None;
        session.join_history_prefix.clear();
        value
    } else if let Request::CreateWorkspace {
        display_name,
        workspace_name,
    } = request
    {
        if session.workspace.is_some() || session.pending_join.is_some() {
            return Err("session already owns a workspace".into());
        }
        transition_activity(session, WorkspacePhase::Creating, None)?;
        let workspace = arachne_security::Workspace::create_named(
            session.node.id(),
            &display_name,
            workspace_name.as_deref(),
        )
        .map_err(|error| {
            let _ = transition_activity(session, WorkspacePhase::Failed, Some("create_failed"));
            error.to_string()
        })?;
        transition_activity(session, WorkspacePhase::Active, None)?;
        let value = json!({"workspace": workspace.id(), "workspace_name":workspace.workspace_name().map_err(str::to_owned)?, "epoch": workspace.epoch(),
            "members": workspace.member_count(), "member": member_metadata(&workspace), "durable": false});
        let mut value = value;
        commit_workspace(session, workspace);
        value["activity"] = activity_value(session);
        value
    } else if matches!(request, Request::SealWorkspace {}) {
        if session.records.is_some() {
            return Err(
                "native records already own persistence; save staged candidates directly".into(),
            );
        }
        if session.staged_workspace.is_some()
            || session.inbound_admission.is_some()
            || !session.queued_admission_in_flight.is_empty()
        {
            return Err("admission candidate awaits durable adoption or reply".into());
        }
        let workspace = session
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?;
        let key = session
            .storage_key
            .as_ref()
            .ok_or("session has no protected root key")?;
        let snapshot = seal_state(
            session.records.is_some(),
            workspace,
            key,
            session.publisher.as_ref(),
            session.received.as_ref(),
            session.inbox.as_ref(),
        )?;
        json!({"workspace": workspace.id(), "snapshot": snapshot})
    } else if let Request::RestoreWorkspace {
        workspace,
        snapshot,
    } = request
    {
        if session.workspace.is_some() || session.pending_join.is_some() {
            return Err("session already owns a workspace".into());
        }
        let key = session
            .storage_key
            .as_ref()
            .ok_or("session has no protected root key")?;
        if snapshot.starts_with(b"DFRM") {
            let removed = arachne_security::RemovedMembership::restore(
                key,
                session.node.id(),
                workspace,
                &snapshot,
            )
            .map_err(str::to_owned)?;
            let value = json!({"workspace":removed.workspace_id(), "epoch":removed.epoch(),
                "state":"removed", "member":{"id":removed.member().id(), "display_name":removed.member().display_name()},
                "commit_digest":removed.commit_digest(), "workspace_ready":false});
            // Consume the owner before releasing the lock. Even a caller which
            // ignores the removed state cannot install fixture policy or reload
            // an older active snapshot on this session. Close transport/tasks too.
            *ended = Some(guard.take().ok_or("node is closed")?);
            return Ok(value);
        }
        let (restored, publisher, received, inbox) = if snapshot.starts_with(b"DFWB\x01") {
            let (_, attachment) = arachne_security::Workspace::restore_with_attachment(
                key,
                session.node.id(),
                workspace,
                &snapshot,
            )
            .map_err(str::to_owned)?;
            if attachment.starts_with(b"DFOI\x01") {
                let (owner, log, inbox) = arachne_delivery::inbox::ObjectInbox::restore(
                    key,
                    session.node.id(),
                    workspace,
                    &snapshot,
                )
                .map_err(str::to_owned)?;
                let received = inbox.legacy_receipts().map_err(str::to_owned)?;
                (owner, Some(log), received, Some(inbox))
            } else {
                let (owner, log, received) = arachne_delivery::PublisherLog::restore_with_receipts(
                    key,
                    session.node.id(),
                    workspace,
                    &snapshot,
                )
                .map_err(str::to_owned)?;
                let (_, attachment) = arachne_security::Workspace::restore_with_attachment(
                    key,
                    session.node.id(),
                    workspace,
                    &snapshot,
                )
                .map_err(str::to_owned)?;
                let received = attachment.starts_with(b"DFDL\x01").then_some(received);
                (owner, Some(log), received, None)
            }
        } else {
            (
                arachne_security::Workspace::restore(key, session.node.id(), workspace, &snapshot)
                    .map_err(str::to_owned)?,
                None,
                None,
                None,
            )
        };
        transition_activity(session, WorkspacePhase::Active, None)?;
        let value = json!({"workspace": restored.id(), "workspace_name":restored.workspace_name().map_err(str::to_owned)?, "epoch": restored.epoch(),
            "workspace_name_missing_history":restored.workspace_name_missing_history().map_err(str::to_owned)?,
            "members": restored.member_count(), "member": member_metadata(&restored), "durable": false});
        session.publisher = publisher;
        session.received = received;
        session.inbox = inbox;
        commit_workspace(session, restored);
        let mut value = value;
        value["activity"] = activity_value(session);
        value
    } else if matches!(
        request,
        Request::Subscribe { .. } | Request::Unsubscribe { .. }
    ) && !session.interests.is_idle()
    {
        // A blocking legacy operation cannot bypass queued newer choices.
        return Err("interest repair is active; use set_interest".into());
    } else if let Request::SetInterest {
        workspace,
        revision,
        topic,
        subscribed,
    } = request
    {
        session.interests.set(
            &session.node,
            &session.runtime,
            interest::Update {
                workspace,
                revision,
                topic,
                subscribed,
            },
        )?
    } else if matches!(request, Request::PollInterest {}) {
        session.interests.poll(&session.node, &session.runtime)
    } else if matches!(request, Request::Poll {}) {
        match session.receiver.try_recv() {
            Ok(message) => json!({"workspace": message.workspace, "revision": message.revision,
                "sender": message.sender, "topic": message.topic.as_str(), "payload": message.payload}),
            Err(mpsc::error::TryRecvError::Empty) => Value::Null,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return Err("event receiver closed".into());
            }
        }
    } else {
        session.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                let node = &session.node;
                let result = match request {
                    Request::AddAddressHint { peer, address } => {
                        node.add_address_hint(
                            peer,
                            address.parse().map_err(|_| "invalid socket address")?,
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                        session.interests.repair();
                        Value::Null
                    }
                    Request::InstallWorkspacePolicy { revision } => {
                        let owner = session.workspace.as_ref().ok_or("session has no workspace")?;
                        if owner.epoch().checked_add(1) != Some(revision) {
                            return Err("workspace policy revision must match current epoch".into());
                        }
                        let policy = owner.member_endpoints().map_err(str::to_owned)?.into_iter()
                            .map(|endpoint| (endpoint, Permissions::AllTopics)).collect();
                        install_gossip_policy(
                            node,
                            &mut session.overlay_paths,
                            owner.id(),
                            revision,
                            policy,
                        )
                        .await?;
                        session.interests.replace_revision(owner.id(), revision);
                        json!({"workspace":owner.id(), "revision":revision, "members":owner.member_count()})
                    }
                    Request::InstallMemberPolicy { revision, topics } => {
                        let workspace = session
                            .workspace
                            .as_ref()
                            .ok_or("session has no workspace")?;
                        let topics = topics
                            .into_iter()
                            .map(Topic::new)
                            .collect::<Result<BTreeSet<_>, _>>()
                            .map_err(|e| e.to_string())?;
                        if topics.is_empty() {
                            return Err("member policy requires an explicit topic set".into());
                        }
                        let mut policy = BTreeMap::new();
                        for endpoint in workspace.member_endpoints().map_err(str::to_owned)? {
                            if policy
                                .insert(
                                    endpoint,
                                    Permissions::Selected {
                                        publish: topics.clone(),
                                        subscribe: topics.clone(),
                                    },
                                )
                                .is_some()
                            {
                                return Err("duplicate member endpoint".into());
                            }
                        }
                        install_gossip_policy(
                            node,
                            &mut session.overlay_paths,
                            workspace.id(),
                            revision,
                            policy,
                        )
                        .await?;
                        session.interests.replace_revision(workspace.id(), revision);
                        json!({"workspace":workspace.id(), "revision":revision,
                            "members":workspace.member_count()})
                    }
                    Request::InstallVerifiedPolicy {
                        workspace,
                        revision,
                        endpoints,
                    } => {
                        let mut policy = BTreeMap::new();
                        for endpoint in endpoints {
                            let access = Permissions::Selected {
                                publish: endpoint
                                    .publish
                                    .into_iter()
                                    .map(Topic::new)
                                    .collect::<Result<BTreeSet<_>, _>>()
                                    .map_err(|e| e.to_string())?,
                                subscribe: endpoint
                                    .subscribe
                                    .into_iter()
                                    .map(Topic::new)
                                    .collect::<Result<BTreeSet<_>, _>>()
                                    .map_err(|e| e.to_string())?,
                            };
                            if policy.insert(endpoint.peer, access).is_some() {
                                return Err("duplicate endpoint".into());
                            }
                        }
                        node.install_verified_policy(workspace, revision, policy)
                            .await
                            .map_err(|e| e.to_string())?;
                        session.interests.replace_revision(workspace, revision);
                        Value::Null
                    }
                    Request::Subscribe {
                        workspace,
                        revision,
                        topic,
                    } => report(
                        node.subscribe(
                            workspace,
                            revision,
                            Topic::new(topic).map_err(|e| e.to_string())?,
                        )
                        .await
                        .map_err(|e| e.to_string())?,
                    ),
                    Request::Unsubscribe {
                        workspace,
                        revision,
                        topic,
                    } => report(
                        node.unsubscribe(
                            workspace,
                            revision,
                            Topic::new(topic).map_err(|e| e.to_string())?,
                        )
                        .await
                        .map_err(|e| e.to_string())?,
                    ),
                    Request::Publish {
                        workspace,
                        revision,
                        topic,
                        payload,
                    } => report(
                        node.publish(
                            workspace,
                            revision,
                            Topic::new(topic).map_err(|e| e.to_string())?,
                            payload,
                        )
                        .await
                        .map_err(|e| e.to_string())?,
                    ),
                    Request::Resource { .. }
                    | Request::WorkspaceMetrics {}
                    | Request::WorkspaceState {}
                    | Request::ResetWorkspace {}
                    | Request::NetworkChange {}
                    | Request::NearbyEndpoints {}
                    | Request::SetNearbyIdentity { .. }
                    | Request::NearbyWorkspaces {}
                    | Request::SetNearbyWorkspace { .. }
                    | Request::SendNearbyInvitation { .. }
                    | Request::EndpointInfo {}
                    | Request::ControlExchange { .. }
                    | Request::StageNetworkPublication { .. }
                    | Request::PollProtected {}
                    | Request::StagePublication { .. }
                    | Request::AdoptPublication { .. }
                    | Request::StageReception { .. }
                    | Request::AdoptReception { .. }
                    | Request::AdoptRecovery { .. }
                    | Request::JoinViaPeer { .. }
                    | Request::DriveJoin {}
                    | Request::FetchInvitationCheckpoint { .. }
                    | Request::DiscoverRecoveryCutoff { .. }
                    | Request::PollRecoveryCutoff {}
                    | Request::FetchRecoveryRange { .. }
                    | Request::PollRecoveryRange {}
                    | Request::StageRecoveryRange { .. }
                    | Request::NextDirectGap {}
                    | Request::FetchDirectRecovery { .. }
                    | Request::PollDirectRecovery {}
                    | Request::StageDirectRecovery {}
                    | Request::StageDirectMiss {}
                    | Request::CancelDirectRecovery {}
                    | Request::FetchCurrentView { .. }
                    | Request::PollCurrentView {}
                    | Request::StageCurrentView {}
                    | Request::AdoptCurrentView { .. }
                    | Request::CancelCurrentView {}
                    | Request::PollRecoveredPublication {}
                    | Request::CancelRecoveryRange {}
                    | Request::PollAdmission { .. }
                    | Request::DriveWorkspace {}
                    | Request::ListAdmissionApprovals { .. }
                    | Request::AcknowledgeAdmissionApproval { .. }
                    | Request::SendAdmissionReply {}
                    | Request::StageJoin { .. }
                    | Request::AdoptJoin { .. }
                    | Request::FetchMembershipUpdate { .. }
                    | Request::PollMembershipUpdate {}
                    | Request::PollWorkspacePresence { .. }
                    | Request::NextMembershipPeer { .. }
                    | Request::OfferMembershipUpdate { .. }
                    | Request::OfferStagedMembershipUpdate { .. }
                    | Request::PollMembershipOffer {}
                    | Request::DiscardWorkspaceCandidate {}
                    | Request::MemberRoster { .. }
                    | Request::UseServiceProfile {}
                    | Request::LeaveViaPeer { .. }
                    | Request::StageSoloLeave {}
                    | Request::StageInvitation { .. }
                    | Request::StageInvitationApproval { .. }
                    | Request::StageInvitationDecline { .. }
                    | Request::InvitationControls {}
                    | Request::StageManagement { .. }
                    | Request::StageWorkspaceName { .. }
                    | Request::StageWorkspaceNameUpdate { .. }
                    | Request::StageWorkspaceNameCheckpoint { .. }
                    | Request::InspectInvitation { .. }
                    | Request::StageAdmissionUpdate { .. }
                    | Request::StageAdmission { .. }
                    | Request::AdoptAdmission { .. }
                    | Request::RetainedAdmission { .. }
                    | Request::Poll {}
                    | Request::IssueInvitation {}
                    | Request::BeginJoin { .. }
                    | Request::SealPendingJoin {}
                    | Request::RestorePendingJoin { .. }
                    | Request::CreateWorkspace { .. }
                    | Request::SealWorkspace {}
                    | Request::EnableObjectDelivery {}
                    | Request::PollPendingObject { .. }
                    | Request::StageObjectAcknowledgement { .. }
                    | Request::StageObjectRejection { .. }
                    | Request::RestoreWorkspace { .. }
                    | Request::SetInterest { .. }
                    | Request::PollInterest {} => unreachable!(),
                };
                Ok::<_, String>(result)
            })
            .await
            .map_err(|_| "operation deadline exceeded; outcome may be partial".to_string())?
        })?
    };
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_lifecycle_retries_after_the_last_peer() {
        let peers = vec![[1; 32], [2; 32]];
        let mut lifecycle = JoinLifecycle::new(peers.clone()).unwrap();
        lifecycle.selected = Some(peers[0]);
        lifecycle.advance();
        assert_eq!(lifecycle.cursor, 1);
        assert_eq!(lifecycle.selected, None);
        lifecycle.selected = Some(peers[1]);
        lifecycle.advance();
        assert_eq!(lifecycle.cursor, 0);
        assert_eq!(lifecycle.selected, None);
    }

    #[test]
    fn admission_batch_wire_sizes_fit_transport_bounds() {
        use arachne_security::{
            AdmissionAssessment, MembershipAuthorization, PendingJoin, Workspace,
        };

        for count in [8, MAX_RUNTIME_ADMISSION_BATCH] {
            let endpoint = |index: usize| {
                let mut value = [0; 32];
                value[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
                value
            };
            let mut owner = Workspace::create(endpoint(10_000), "Wire-size owner").unwrap();
            let (invitation, checkpoint) = owner.issue_invitation().unwrap();
            let mut joins = Vec::with_capacity(count);
            let mut requests = Vec::with_capacity(count);
            let mut validated = Vec::with_capacity(count);
            for index in 0..count {
                let join = PendingJoin::from_invitation(
                    &invitation,
                    &checkpoint,
                    endpoint(index + 20_000),
                    "Wire-size member",
                )
                .unwrap();
                let request = join.admission_request().unwrap().to_vec();
                let validated_request = match owner
                    .assess_admission(endpoint(index + 20_000), &request)
                    .unwrap()
                {
                    AdmissionAssessment::Ready(request) => request,
                    _ => panic!("wire-size invitation unexpectedly needs approval"),
                };
                joins.push(join);
                requests.push(request);
                validated.push(validated_request);
            }
            let entries: Vec<_> = (0..count)
                .map(|index| {
                    (
                        endpoint(index + 20_000),
                        requests[index].as_slice(),
                        &validated[index],
                    )
                })
                .collect();
            let prepared = owner.prepare_validated_admission_batch(&entries).unwrap();
            let authorization = MembershipAuthorization::AdmissionBatch(
                prepared
                    .replies
                    .iter()
                    .map(|reply| reply.authorization.clone())
                    .collect(),
            );
            let step = membership::step_json(&authorization, &prepared.commit);
            let mut offer = b"DFMO\x01".to_vec();
            offer.extend(prepared.workspace.id());
            offer.extend(0_u64.to_be_bytes());
            offer.extend(serde_json::to_vec(&step).unwrap());
            let mut reply =
                retained_reply(&prepared.workspace, endpoint(20_000), &requests[0]).unwrap();
            reply["commits"] = json!([step]);
            let reply = serde_json::to_vec(&reply).unwrap();
            println!(
                "admission_wire_size count={count} offer_bytes={} reply_bytes={}",
                offer.len(),
                reply.len()
            );
            assert!(
                offer.len() <= 32 * 1024,
                "offer exceeds control request bound"
            );
            assert!(
                reply.len() <= arachne_node::MAX_CONTROL_REPLY,
                "reply exceeds control response bound"
            );
            owner = prepared.workspace;
            assert_eq!(owner.member_count(), count + 1);
            assert_eq!(joins.len(), count);
        }
    }

    #[test]
    #[ignore = "explicit 500-member runtime history-page capacity run"]
    fn admission_history_pages_handle_500_member_burst() {
        use arachne_security::{AdmissionAssessment, PendingJoin, Workspace};

        let started = std::time::Instant::now();
        let endpoint = |index: usize| {
            let mut value = [0; 32];
            value[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            value
        };
        let mut owner = Workspace::create(endpoint(10_000), "500-member owner").unwrap();
        let (invitation, checkpoint) = owner.issue_invitation().unwrap();
        let mut joins = Vec::with_capacity(500);
        let mut requests = Vec::with_capacity(500);
        let mut validated = Vec::with_capacity(500);
        for index in 0..500 {
            let remote = endpoint(index + 20_000);
            let join =
                PendingJoin::from_invitation(&invitation, &checkpoint, remote, "Burst member")
                    .unwrap();
            let request = join.admission_request().unwrap().to_vec();
            let validated_request = match owner.assess_admission(remote, &request).unwrap() {
                AdmissionAssessment::Ready(request) => request,
                _ => panic!("500-member invitation unexpectedly needs approval"),
            };
            joins.push(join);
            requests.push(request);
            validated.push(validated_request);
        }

        let mut welcome = Vec::new();
        let mut batches = 0;
        for start in (0..500).step_by(MAX_RUNTIME_ADMISSION_BATCH) {
            let end = (start + MAX_RUNTIME_ADMISSION_BATCH).min(500);
            let entries: Vec<_> = (start..end)
                .map(|index| {
                    (
                        endpoint(index + 20_000),
                        requests[index].as_slice(),
                        &validated[index],
                    )
                })
                .collect();
            let prepared = owner.prepare_validated_admission_batch(&entries).unwrap();
            welcome = prepared.welcome.clone();
            owner = prepared.workspace;
            batches += 1;
            if batches % 8 == 0 || end == 500 {
                eprintln!("memory members={end} {:?}", owner.memory_report());
            }
        }

        let target = joins.last().unwrap();
        let target_endpoint = endpoint(20_499);
        let target_request = target.admission_request().unwrap();
        let mut offset = 0;
        let mut pages = 0;
        let mut commits = Vec::new();
        let mut page_ms = Vec::new();
        let mut page_bytes = Vec::new();
        loop {
            let page_started = std::time::Instant::now();
            let encoded = admission_reply_page(
                &owner,
                target_endpoint,
                target_request,
                Some(&checkpoint),
                offset,
            )
            .unwrap();
            page_ms.push(page_started.elapsed().as_secs_f64() * 1000.0);
            page_bytes.push(encoded.len());
            assert!(encoded.len() <= arachne_node::MAX_CONTROL_REPLY);
            let page: Value = serde_json::from_slice(&encoded).unwrap();
            commits.extend(page["commits"].as_array().unwrap().iter().cloned());
            pages += 1;
            if page["history_complete"].as_bool().unwrap() {
                break;
            }
            offset = page["history_next"].as_u64().unwrap() as usize;
        }
        assert_eq!(commits.len(), batches);

        let mut proof = target.join_proof().unwrap();
        for commit in commits {
            let step: JoinStep = serde_json::from_value(commit).unwrap();
            proof
                .apply_transition(&step.authorization().unwrap(), &step.commit)
                .unwrap();
        }
        let joined = target.prepare_workspace(&proof, &welcome).unwrap();
        assert_eq!(joined.member_count(), 501);
        println!(
            "admission_runtime_capacity members=500 batches={batches} pages={pages} elapsed_ms={} page_ms={page_ms:.1?} page_bytes={page_bytes:?}",
            started.elapsed().as_millis()
        );
    }

    #[test]
    fn pending_object_query_bounds_and_gap_epoch_guard() {
        use arachne_delivery::{
            PublisherLog,
            inbox::{InboxStage, ObjectInbox},
        };
        use arachne_routing::PublicationContext;
        use arachne_security::{PendingJoin, StorageKey, Workspace};

        let root = [103; 32];
        let handle = create(Some(&root)).unwrap();
        let call = |request: Value| -> Result<Value, String> {
            serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
                .map_err(|error| error.to_string())
        };
        let description: Value = serde_json::from_str(&describe(handle).unwrap()).unwrap();
        let endpoint = serde_json::from_value(description["endpoint_key"].clone()).unwrap();
        let admin = Workspace::create([104; 32], "Publisher").unwrap();
        let (invitation, checkpoint) = admin.issue_invitation().unwrap();
        let join =
            PendingJoin::from_invitation(&invitation, &checkpoint, endpoint, "Reader").unwrap();
        let prepared = admin
            .prepare_admission(endpoint, join.admission_request().unwrap())
            .unwrap();
        let mut proof = join.join_proof().unwrap();
        proof
            .apply_add(&prepared.authorization, &prepared.commit)
            .unwrap();
        let reader = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
        let mut sender = prepared.workspace;
        let mut inbox = ObjectInbox::new(reader.id(), reader.epoch());
        for direct in [true, false] {
            let context = PublicationContext {
                workspace: reader.id(),
                revision: 7,
                topic: Topic::new("chat/messages").unwrap(),
                id: [if direct { 1 } else { 2 }; 16],
                sequence: std::num::NonZeroU64::new(2),
            };
            let recipients = if direct {
                vec![reader.member().unwrap().id()]
            } else {
                vec![]
            };
            let aad = if direct {
                context.direct_authenticated_bytes(&recipients).unwrap()
            } else {
                context.authenticated_bytes()
            };
            let object = sender.protect_object(&aad, b"pending").unwrap();
            let InboxStage::Prepared(next) = inbox
                .stage_with_recipients(&reader, &context, &recipients, &object)
                .unwrap()
            else {
                panic!("object was not staged")
            };
            inbox = *next;
        }
        let publisher =
            PublisherLog::new(reader.id(), reader.member().unwrap().id(), reader.epoch());
        let snapshot = inbox
            .seal(&reader, &StorageKey::derive(&root).unwrap(), &publisher)
            .unwrap();
        call(json!({"op":"restore_workspace","workspace":reader.id(),"snapshot":snapshot}))
            .unwrap();
        let pending = call(json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(pending["id"], json!(vec![2; 16]));
        assert_eq!(
            call(json!({"op":"poll_pending_object","deferred":[]})).unwrap(),
            pending
        );
        let scope = json!({"member":pending["member"], "revision":pending["revision"],
            "topic":pending["topic"], "recipients":pending["recipients"]});
        let poll = |deferred: Value| call(json!({"op":"poll_pending_object","deferred":deferred}));
        // The group is deferred and the direct object still waits behind sequence 1.
        assert_eq!(poll(json!([scope])).unwrap(), Value::Null);
        assert_eq!(poll(json!(vec![scope.clone(); 64])).unwrap(), Value::Null);
        assert_eq!(
            poll(json!(vec![scope.clone(); 65])).unwrap_err(),
            "too many deferred delivery streams"
        );
        let mut audience = scope.clone();
        audience["recipients"] = json!((0..64u8).map(|number| [number; 32]).collect::<Vec<_>>());
        assert_eq!(poll(json!([audience])).unwrap(), pending);
        for (field, value) in [
            ("revision", json!(0)),
            ("topic", json!("")),
            ("topic", json!("chat//messages")),
            ("topic", json!("a".repeat(129))),
            ("recipients", json!(vec![[1; 32], [1; 32]])),
            ("recipients", json!(vec![[2; 32], [1; 32]])),
            (
                "recipients",
                json!((0..65u8).map(|number| [number; 32]).collect::<Vec<_>>()),
            ),
        ] {
            let mut invalid = scope.clone();
            invalid[field] = value;
            assert_eq!(
                poll(json!([invalid])).unwrap_err(),
                "invalid deferred delivery stream"
            );
        }
        for (field, value) in [
            ("member", json!(vec![1; 31])),
            ("author", json!(vec![1; 32])),
            ("revision", json!(-1)),
            ("recipients", json!(vec![[1; 31]])),
        ] {
            let mut invalid = scope.clone();
            invalid[field] = value;
            assert!(poll(json!([invalid])).is_err());
        }
        assert!(poll(Value::Null).is_err());
        assert_eq!(call(json!({"op":"poll_pending_object"})).unwrap(), pending);
        {
            let shared = session(handle).unwrap();
            let mut locked = shared.lock().unwrap();
            assert!(check_epoch_transition(locked.as_mut().unwrap()).is_err());
        }
        let staged = call(
            json!({"op":"stage_object_acknowledgement", "member":pending["member"],
            "topic":pending["topic"], "counter":pending["counter"], "id":pending["id"]}),
        )
        .unwrap();
        call(json!({"op":"adopt_reception","snapshot":staged["snapshot"]})).unwrap();
        assert_eq!(
            call(json!({"op":"poll_pending_object"})).unwrap(),
            Value::Null
        );
        {
            let shared = session(handle).unwrap();
            let mut locked = shared.lock().unwrap();
            let owner = locked.as_mut().unwrap();
            assert_eq!(owner.inbox.as_ref().unwrap().pending_count(), 1);
            assert_eq!(
                check_epoch_transition(owner).unwrap_err(),
                "pending application delivery must be acknowledged before membership update"
            );
        }
        close(handle).unwrap();
    }

    #[test]
    fn overlay_path_budget_fails_closed_and_releases() {
        let total = AtomicUsize::new(0);
        assert!(reserve_overlay_paths(&total, MAX_DEVICE_OVERLAY_PATHS));
        assert!(!reserve_overlay_paths(&total, 1));
        release_overlay_paths(&total, MAX_DEVICE_OVERLAY_PATHS);
        assert_eq!(total.load(Ordering::Acquire), 0);
        assert!(reserve_overlay_paths(&total, 5));
        assert_eq!(total.load(Ordering::Acquire), 5);
    }

    #[test]
    fn real_node_lifecycle_rejects_stale_handles_and_releases_capacity() {
        assert!(describe(0).is_err());
        assert!(close(-1).is_err());
        let handles: Vec<_> = (0..8).map(|_| create(None).unwrap()).collect();
        assert!(create(None).is_err());
        for handle in &handles {
            let info: serde_json::Value =
                serde_json::from_str(&describe(*handle).unwrap()).unwrap();
            assert_eq!(info["endpoint_key"].as_array().unwrap().len(), 32);
            assert_eq!(info["workspace_ready"], false);
            close(*handle).unwrap();
            assert!(describe(*handle).is_err());
            assert!(close(*handle).is_err());
        }
        let next = create(None).unwrap();
        assert!(next > *handles.last().unwrap());
        close(next).unwrap();

        // Exercise the same request dispatcher exported over JNI with real peers.
        let a = create(None).unwrap();
        let b = create(None).unwrap();
        let ai: Value = serde_json::from_str(&describe(a).unwrap()).unwrap();
        let bi: Value = serde_json::from_str(&describe(b).unwrap()).unwrap();
        let call = |handle, value: Value| -> Result<Value, String> {
            serde_json::from_slice(&execute(handle, &serde_json::to_vec(&value).unwrap())?)
                .map_err(|e| e.to_string())
        };
        assert_eq!(
            call(a, json!({"op":"network_change"})).unwrap(),
            json!({"notified":true})
        );
        for (handle, other) in [(a, &bi), (b, &ai)] {
            let port = other["bound_address"]
                .as_str()
                .unwrap()
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .port();
            call(
                handle,
                json!({"op":"add_address_hint", "peer":other["endpoint_key"],
                "address":format!("127.0.0.1:{port}")}),
            )
            .unwrap();
            call(
                handle,
                json!({"op":"install_verified_policy", "workspace":vec![7;32], "revision":1,
                "endpoints":[
                    {"peer":ai["endpoint_key"], "publish":["streams/sample"], "subscribe":[]},
                    {"peer":bi["endpoint_key"], "publish":[], "subscribe":["streams/sample"]}
                ]}),
            )
            .unwrap();
        }
        call(b, json!({"op":"subscribe", "workspace":vec![7;32], "revision":1, "topic":"streams/sample"})).unwrap();
        for payload in [vec![0, 255, 17], br#"{"event":"changed"}"#.to_vec()] {
            let outcome = call(
                a,
                json!({"op":"publish", "workspace":vec![7;32], "revision":1,
                "topic":"streams/sample", "payload":payload}),
            )
            .unwrap();
            assert_eq!(outcome["admitted"], json!([bi["endpoint_key"]]));
            assert_eq!(outcome["failed"], json!([]));
            let received = call(b, json!({"op":"poll"})).unwrap();
            assert_eq!(received["payload"], json!(payload));
            assert_eq!(received["workspace"], json!(vec![7; 32]));
            assert_eq!(received["sender"], ai["endpoint_key"]);
        }
        assert_eq!(call(b, json!({"op":"poll"})).unwrap(), Value::Null);
        assert!(
            call(
                b,
                json!({"op":"publish", "workspace":vec![7;32], "revision":1,
            "topic":"streams/sample", "payload":[1]})
            )
            .is_err()
        );
        assert!(call(a, json!({"op":"poll", "unexpected":true})).is_err());
        assert!(execute(a, &vec![b' '; MAX_REQUEST + 1]).is_err());
        call(b, json!({"op":"unsubscribe", "workspace":vec![7;32], "revision":1, "topic":"streams/sample"})).unwrap();
        assert_eq!(
            call(
                a,
                json!({"op":"publish", "workspace":vec![7;32], "revision":1,
            "topic":"streams/sample", "payload":[1]})
            )
            .unwrap()["admitted"],
            json!([])
        );
        close(a).unwrap();
        close(b).unwrap();
        assert!(call(a, json!({"op":"poll"})).is_err());

        let mut admin = create(Some(&[41; 32])).unwrap();
        let joiner = create(Some(&[42; 32])).unwrap();
        let created = call(
            admin,
            json!({"op":"create_workspace","display_name":"Coordinator"}),
        )
        .unwrap();
        let old = call(admin, json!({"op":"seal_workspace"})).unwrap();
        let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
        let pending = call(
            joiner,
            json!({"op":"begin_join","invitation":invite["invitation"],
            "checkpoint":invite["checkpoint"],"display_name":"Field member"}),
        )
        .unwrap();
        let stage = json!({"op":"stage_admission","authenticated_endpoint":pending["endpoint"],"request":pending["admission_request"]});
        let retry = json!({"op":"retained_admission","authenticated_endpoint":pending["endpoint"],"request":pending["admission_request"]});
        let prepared = call(admin, stage.clone()).unwrap();
        assert!(prepared.get("welcome").is_none());
        assert!(call(admin, retry.clone()).is_err());
        assert!(call(admin, json!({"op":"seal_workspace"})).is_err());
        assert!(
            call(
                admin,
                json!({"op":"adopt_admission","snapshot":old["snapshot"]})
            )
            .is_err()
        );
        close(admin).unwrap(); // No candidate saved: the old durable state wins.
        admin = create(Some(&[41; 32])).unwrap();
        let restored = call(admin, json!({"op":"restore_workspace","workspace":created["workspace"],"snapshot":old["snapshot"]})).unwrap();
        assert_eq!(restored["members"], 1);
        assert!(call(admin, retry.clone()).is_err());
        let saved = call(admin, stage).unwrap();
        close(admin).unwrap(); // Candidate saved, adoption reply lost: restore it directly.
        admin = create(Some(&[41; 32])).unwrap();
        let restored = call(admin, json!({"op":"restore_workspace","workspace":created["workspace"],"snapshot":saved["snapshot"]})).unwrap();
        assert_eq!(restored["members"], 2);
        assert_eq!(restored["epoch"], 1);
        let reply = call(admin, retry.clone()).unwrap();
        assert_eq!(reply["welcome"], call(admin, retry).unwrap()["welcome"]);
        call(
            joiner,
            json!({"op":"add_address_hint", "peer":invite["peer"],
            "address":serde_json::from_str::<Value>(&describe(admin).unwrap()).unwrap()["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")}),
        )
        .unwrap();
        let peer = invite["peer"].clone();
        let requesting = std::thread::spawn(move || {
            let request =
                serde_json::to_vec(&json!({"op":"request_admission","peer":peer})).unwrap();
            serde_json::from_slice::<Value>(&execute(joiner, &request).unwrap()).unwrap()
        });
        // The result is retained, so this request is an inquiry (ADR 0010): the
        // committed view answers it and the host is never asked.
        let mut network_reply = requesting.join().unwrap();
        assert_eq!(
            call(admin, json!({"op":"poll_admission"})).unwrap(),
            Value::Null
        );
        // The joiner reports the wire size of every page it accepted; a
        // one-page history still reports its single page.
        let pages = network_reply
            .as_object_mut()
            .unwrap()
            .remove("history_page_bytes")
            .unwrap();
        assert_eq!(pages.as_array().unwrap().len(), 1);
        assert!(
            pages[0].as_u64().unwrap() as usize <= arachne_node::MAX_CONTROL_REPLY,
            "a served page must stay inside the control-reply bound"
        );
        assert_eq!(
            network_reply
                .as_object_mut()
                .unwrap()
                .remove("commits")
                .unwrap(),
            json!([{"commit":reply["commit"],"authorization":reply["authorization"]}])
        );
        assert_eq!(network_reply, reply);
        let join = json!({"op":"stage_join", "welcome":reply["welcome"],
            "commits":[{"commit":reply["commit"], "authorization":reply["authorization"]}]});
        let mut invalid = join.clone();
        invalid["commits"][0]["authorization"]["grant_signature"] = json!([1]);
        assert!(call(joiner, invalid).is_err());
        assert!(call(joiner, json!({"op":"seal_pending_join"})).is_ok());
        let staged_join = call(joiner, join).unwrap();
        assert!(
            call(
                joiner,
                json!({"op":"adopt_admission","snapshot":staged_join["snapshot"]})
            )
            .is_err()
        );
        let adopted = call(
            joiner,
            json!({"op":"adopt_join","snapshot":staged_join["snapshot"]}),
        )
        .unwrap();
        assert_eq!(adopted["members"], 2);
        assert!(call(joiner, json!({"op":"seal_pending_join"})).is_err());
        close(joiner).unwrap();
        let joiner = create(Some(&[42; 32])).unwrap();
        let restored = call(joiner,json!({"op":"restore_workspace","workspace":created["workspace"],"snapshot":staged_join["snapshot"]})).unwrap();
        assert_eq!(restored["member"], pending["member"]);
        // Production routing obtains endpoints from the restored MLS roster.
        let member_policy =
            json!({"op":"install_member_policy","revision":17,"topics":["streams/sample"]});
        for handle in [admin, joiner] {
            assert!(call(handle, json!({"op":"install_verified_policy","workspace":created["workspace"],"revision":17,"endpoints":[]})).is_err());
            assert!(
                call(
                    handle,
                    json!({"op":"install_member_policy","revision":17,"topics":[]})
                )
                .is_err()
            );
            assert!(
                call(
                    handle,
                    json!({"op":"install_member_policy","revision":17,"topics":["bad topic"]})
                )
                .is_err()
            );
            let installed = call(handle, member_policy.clone()).unwrap();
            assert_eq!(installed["members"], 2);
            assert_eq!(installed["revision"], 17);
            assert!(call(handle, member_policy.clone()).is_err());
        }
        // The policy authorizes real peer subscription without injecting keys.
        let admin_info: Value = serde_json::from_str(&describe(admin).unwrap()).unwrap();
        call(joiner, json!({"op":"add_address_hint","peer":admin_info["endpoint_key"],
            "address":admin_info["bound_address"].as_str().unwrap().replace("0.0.0.0:","127.0.0.1:")})).unwrap();
        let subscribed = call(joiner, json!({"op":"subscribe","workspace":created["workspace"],"revision":17,"topic":"streams/sample"})).unwrap();
        assert_eq!(subscribed["admitted"].as_array().unwrap().len(), 2);
        assert!(subscribed["failed"].as_array().unwrap().is_empty());
        assert!(call(joiner, json!({"op":"subscribe","workspace":created["workspace"],"revision":17,"topic":"streams/other"})).is_err());
        let staged_binary = execute_stored(admin, &serde_json::to_vec(&json!({"op":"stage_network_publication","revision":17,"topic":"streams/sample","id":vec![10;16],"payload":[0,255,77]})).unwrap(), &[]).unwrap();
        let mut staged_network: Value = serde_json::from_slice(&staged_binary[0]).unwrap();
        assert!(staged_network.get("snapshot").is_none());
        assert!(!staged_binary[1].is_empty());
        staged_network["snapshot"] = json!(staged_binary[1]);
        assert!(staged_network.get("ciphertext").is_none());
        assert_eq!(
            call(joiner, json!({"op":"poll_protected"})).unwrap(),
            Value::Null
        );
        assert!(
            call(
                admin,
                json!({"op":"adopt_publication","snapshot":saved["snapshot"]})
            )
            .is_err()
        );
        let snapshot: Vec<u8> = serde_json::from_value(staged_network["snapshot"].clone()).unwrap();
        assert!(
            execute_stored(
                admin,
                br#"{"op":"adopt_publication","op":"adopt_publication"}"#,
                &snapshot
            )
            .is_err()
        );
        let mut damaged = snapshot.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(execute_stored(admin, br#"{"op":"adopt_publication"}"#, &damaged).is_err());
        assert_eq!(
            call(joiner, json!({"op":"poll_protected"})).unwrap(),
            Value::Null
        );
        assert!(
            execute_stored(
                admin,
                br#"{"op":"adopt_publication","snapshot":[]}"#,
                &snapshot
            )
            .is_err()
        );
        assert!(execute_stored(admin, br#"{"op":"endpoint_info"}"#, &snapshot).is_err());
        assert!(
            execute_stored(
                admin,
                br#"{"op":"adopt_publication"}"#,
                &vec![0; arachne_security::MAX_SEALED_BUNDLE + 1]
            )
            .is_err()
        );
        let sent = execute_stored(admin, br#"{"op":"adopt_publication"}"#, &snapshot).unwrap();
        assert!(sent[1].is_empty());
        let sent: Value = serde_json::from_slice(&sent[0]).unwrap();
        assert!(sent["admission"]["admitted"].as_array().unwrap().is_empty());
        assert_eq!(sent["admission"]["queued"], true);
        assert!(sent["admission"]["failed"].as_array().unwrap().is_empty());
        assert!(sent.get("ciphertext").is_none());
        // Changing only the asserted publisher order invalidates real MLS
        // authentication. The original live packet must remain decryptable.
        let (mut tampered_context, ciphertext) = {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            let log = guard.as_ref().unwrap().publisher.as_ref().unwrap();
            let retained = log
                .select(
                    0,
                    1,
                    &BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                )
                .unwrap();
            let record = retained.records()[0];
            assert_eq!(record.context.sequence.unwrap().get(), record.sequence);
            (record.context.clone(), record.ciphertext.clone())
        };
        tampered_context.sequence = std::num::NonZeroU64::new(2);
        assert!(
            call(
                joiner,
                json!({"op":"stage_reception",
            "context":tampered_context.authenticated_bytes(), "ciphertext":ciphertext})
            )
            .is_err()
        );
        tampered_context.sequence = None;
        assert!(
            call(
                joiner,
                json!({"op":"stage_reception",
            "context":tampered_context.authenticated_bytes(), "ciphertext":ciphertext})
            )
            .is_err()
        );
        let network_received = call(joiner, json!({"op":"poll_protected"})).unwrap();
        assert!(network_received.get("payload").is_none());
        assert_eq!(network_received["state"], "awaiting_reception_save");
        let delivered_network = call(
            joiner,
            json!({"op":"adopt_reception","snapshot":network_received["snapshot"]}),
        )
        .unwrap();
        assert_eq!(delivered_network["payload"], json!([0, 255, 77]));
        assert_eq!(delivered_network["sequence"], 1);
        assert_eq!(delivered_network["id"], json!(vec![10; 16]));
        assert_eq!(delivered_network["member"], created["member"]["id"]);
        assert_eq!(delivered_network["topic"], "streams/sample");
        assert!(call(joiner, json!({"op":"poll"})).is_err());
        call(admin, json!({"op":"subscribe","workspace":created["workspace"],"revision":17,"topic":"streams/sample"})).unwrap();
        let reverse = call(joiner, json!({"op":"stage_network_publication","revision":17,"topic":"streams/sample","id":vec![11;16],"payload":[9]})).unwrap();
        let sent = call(
            joiner,
            json!({"op":"adopt_publication","snapshot":reverse["snapshot"]}),
        )
        .unwrap();
        assert_eq!(sent["admission"]["admitted"].as_array().unwrap().len(), 1);
        assert_eq!(sent["admission"]["queued"], true);
        assert!(sent["admission"]["failed"].as_array().unwrap().is_empty());
        assert_eq!(
            call(joiner, json!({"op":"poll_protected"})).unwrap(),
            Value::Null
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        let incoming = loop {
            let incoming = call(admin, json!({"op":"poll_protected"})).unwrap();
            if !incoming.is_null() {
                break incoming;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        let reverse_delivered = call(
            admin,
            json!({"op":"adopt_reception","snapshot":incoming["snapshot"]}),
        )
        .unwrap();
        assert_eq!(reverse_delivered["payload"], json!([9]));
        assert_eq!(reverse_delivered["member"], pending["member"]["id"]);
        let context = b"workspace/topic/publication".to_vec();
        let publication = json!({"op":"stage_publication","context":context,"payload":[0,255,42]});
        let staged = call(admin, publication.clone()).unwrap();
        assert_eq!(staged["state"], "awaiting_publication_save");
        assert!(staged.get("ciphertext").is_none() && staged.get("payload").is_none());
        assert!(call(admin, publication.clone()).is_err());
        assert!(call(admin, json!({"op":"seal_workspace"})).is_err());
        assert!(
            call(
                admin,
                json!({"op":"adopt_reception","snapshot":staged["snapshot"]})
            )
            .is_err()
        );
        assert!(
            call(
                admin,
                json!({"op":"adopt_publication","snapshot":saved["snapshot"]})
            )
            .is_err()
        );
        let released = call(
            admin,
            json!({"op":"adopt_publication","snapshot":staged["snapshot"]}),
        )
        .unwrap();
        assert!(released.get("ciphertext").is_some());
        assert!(
            call(
                admin,
                json!({"op":"adopt_publication","snapshot":staged["snapshot"]})
            )
            .is_err()
        );
        assert!(call(admin, json!({"op":"publish","workspace":created["workspace"],"revision":1,"topic":"sample","payload":[1]})).is_err());
        let reception =
            json!({"op":"stage_reception","context":context,"ciphertext":released["ciphertext"]});
        let mut wrong = reception.clone();
        wrong["context"] = json!([1]);
        assert!(call(joiner, wrong).is_err());
        // Rejection mutated only a disposable candidate, not the active receiver.
        let received = call(joiner, reception.clone()).unwrap();
        assert_eq!(received["state"], "awaiting_reception_save");
        assert!(received.get("payload").is_none() && received.get("member").is_none());
        assert!(call(joiner, json!({"op":"poll"})).is_err());
        assert!(
            call(
                joiner,
                json!({"op":"adopt_reception","snapshot":staged_join["snapshot"]})
            )
            .is_err()
        );
        let delivered = call(
            joiner,
            json!({"op":"adopt_reception","snapshot":received["snapshot"]}),
        )
        .unwrap();
        assert_eq!(delivered["payload"], json!([0, 255, 42]));
        assert_eq!(delivered["member"], created["member"]["id"]);
        close(joiner).unwrap();
        let joiner = create(Some(&[42; 32])).unwrap();
        call(joiner, json!({"op":"restore_workspace","workspace":created["workspace"],"snapshot":received["snapshot"]})).unwrap();
        assert!(call(joiner, reception).is_err());
        // Simulate process ownership loss after candidate persistence but before
        // adoption. No filesystem/power-loss claim: the record is held in RAM.
        let request = serde_json::to_vec(&json!({"op":"stage_network_publication","revision":17,"topic":"streams/sample","id":vec![12;16],"payload":[7]})).unwrap();
        let candidate = execute_stored(admin, &request, &[]).unwrap();
        assert!(candidate[1].starts_with(b"DFWB\x01"));
        let (head, retained) = {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            let session = guard.as_ref().unwrap();
            assert_eq!(session.publisher.as_ref().unwrap().head(), 1);
            let log = session
                .staged_workspace
                .as_ref()
                .unwrap()
                .publisher
                .as_ref()
                .unwrap();
            assert_eq!(log.head(), 2);
            let range = log
                .select(
                    1,
                    2,
                    &BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                )
                .unwrap();
            (log.head(), range.records()[0].ciphertext.clone())
        };
        close(admin).unwrap();
        admin = create(Some(&[41; 32])).unwrap();
        let restore =
            serde_json::to_vec(&json!({"op":"restore_workspace","workspace":created["workspace"]}))
                .unwrap();
        let mut corrupt = candidate[1].clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(execute_stored(admin, &restore, &corrupt).is_err());
        execute_stored(admin, &restore, &candidate[1]).unwrap();
        {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            let log = guard.as_ref().unwrap().publisher.as_ref().unwrap();
            assert_eq!(log.head(), head);
            let range = log
                .select(
                    1,
                    2,
                    &BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                )
                .unwrap();
            assert_eq!(range.records()[0].ciphertext, retained);
        }
        let next = execute_stored(admin, &serde_json::to_vec(&json!({"op":"stage_network_publication","revision":17,"topic":"streams/sample","id":vec![13;16],"payload":[7]})).unwrap(), &[]).unwrap();
        assert_ne!(candidate[1], next[1]);
        {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            let log = guard
                .as_ref()
                .unwrap()
                .staged_workspace
                .as_ref()
                .unwrap()
                .publisher
                .as_ref()
                .unwrap();
            assert_eq!(log.head(), 3);
            let range = log
                .select(
                    2,
                    3,
                    &BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                )
                .unwrap();
            assert_ne!(range.records()[0].ciphertext, retained);
            let range = log
                .select(
                    1,
                    3,
                    &BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                )
                .unwrap();
            let packets: Vec<_> = range.records().iter().map(|r| (*r).clone()).collect();
            drop(guard);
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            // The committed workspace is never edited in place; read on a copy.
            let mut reader = guard
                .as_ref()
                .unwrap()
                .workspace
                .as_ref()
                .unwrap()
                .provisional_copy()
                .unwrap();
            for packet in packets {
                let context = packet.context.authenticated_bytes();
                assert_eq!(
                    reader
                        .unprotect_application(&context, &packet.ciphertext)
                        .unwrap()
                        .payload,
                    [7]
                );
                assert!(
                    reader
                        .unprotect_application(&context, &packet.ciphertext)
                        .is_err()
                );
            }
        }
        // Admission polling remains available while another candidate is
        // staged so a retry can retrieve an already accepted result.
        assert!(call(admin, json!({"op":"poll_admission"})).is_ok());
        execute_stored(admin, br#"{"op":"adopt_publication"}"#, &next[1]).unwrap();
        call(
            admin,
            json!({"op":"install_member_policy","revision":17,"topics":["streams/sample"]}),
        )
        .unwrap();
        // Exercise actual control dispatch and the node's installed policy.
        let (peer, address, query) = {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            let owner = guard.as_ref().unwrap();
            let workspace = owner.workspace.as_ref().unwrap();
            (
                owner.node.id(),
                std::net::SocketAddr::from(([127, 0, 0, 1], owner.node.address().port())),
                arachne_delivery::RangeQuery {
                    workspace: workspace.id(),
                    author: workspace.member().unwrap().id(),
                    epoch: workspace.epoch(),
                    policy_revision: 17,
                    after: 1,
                    through: 2,
                    topics: BTreeSet::from([Topic::new("streams/sample").unwrap()]),
                },
            )
        };
        // Restoration does not invent authorization. Before the host installs
        // its accepted routing projection, discovery must fail locally.
        assert_eq!(
            call(
                joiner,
                json!({"op":"discover_recovery_cutoff", "peer":peer,
            "revision":17, "topics":["streams/sample"]})
            )
            .unwrap_err(),
            "UnknownWorkspace"
        );
        assert_eq!(
            call(admin, json!({"op":"poll_admission"})).unwrap(),
            Value::Null
        );
        call(
            joiner,
            json!({"op":"install_member_policy", "revision":17,
            "topics":["streams/sample"]}),
        )
        .unwrap();
        let poll_recovery = || {
            let deadline = std::time::Instant::now() + Duration::from_secs(4);
            loop {
                let result = call(admin, json!({"op":"poll_admission"})).unwrap();
                if result != Value::Null {
                    assert_eq!(result["state"], "recovery_replied");
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "recovery dispatch deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let poll_result = |handle, operation: &str| {
            let deadline = std::time::Instant::now() + Duration::from_secs(4);
            loop {
                let result = call(handle, json!({"op":operation}));
                if !matches!(&result, Ok(Value::Null)) {
                    break result;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "cutoff completion deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let poll_cutoff = |handle| poll_result(handle, "poll_recovery_cutoff");
        let poll_range = |handle| poll_result(handle, "poll_recovery_range");
        let exchange = |encoded_query: Vec<u8>| {
            let worker = std::thread::spawn(move || {
                let shared = session(joiner).unwrap();
                let guard = shared.lock().unwrap();
                let owner = guard.as_ref().unwrap();
                owner.runtime.block_on(async {
                    owner.node.add_address_hint(peer, address).await.unwrap();
                    owner
                        .node
                        .request_control(peer, &encoded_query)
                        .await
                        .unwrap()
                })
            });
            poll_recovery();
            worker.join().unwrap()
        };
        let cutoff = arachne_delivery::wire::CutoffQuery {
            workspace: query.workspace,
            author: query.author,
            epoch: query.epoch,
            policy_revision: query.policy_revision,
            topics: query.topics.clone(),
            nonce: [61; 32],
        };
        let cutoff_reply = exchange(cutoff.to_wire().unwrap());
        let discover_request = json!({"op":"discover_recovery_cutoff", "peer":peer,
            "revision":17, "topics":["streams/sample"]});
        // Normal receiver operation owns its nonce and verifies the response.
        let pending = call(joiner, discover_request.clone()).unwrap();
        assert_eq!(pending["state"], "recovery_cutoff_pending");
        assert!(call(joiner, discover_request.clone()).is_err());
        poll_recovery();
        let observed = poll_cutoff(joiner).unwrap();
        assert_eq!(
            call(joiner, json!({"op":"poll_recovery_cutoff"})).unwrap(),
            Value::Null
        );
        assert_eq!(observed["state"], "recovery_cutoff_observed");
        assert_eq!(observed["head"], 3);
        assert_eq!(observed["author"], created["member"]["id"]);
        assert_eq!(observed["accepted_through"], 0);
        assert_eq!(observed["accepted_progress"], false);
        assert!(observed.get("snapshot").is_none() && observed.get("nonce").is_none());
        // Start both peers before servicing either, as serialized Kotlin workers
        // will do. Both starts must return so their existing pollers can run.
        let (joiner_peer, joiner_address) = {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let owner = guard.as_ref().unwrap();
            (
                owner.node.id(),
                std::net::SocketAddr::from(([127, 0, 0, 1], owner.node.address().port())),
            )
        };
        call(
            admin,
            json!({"op":"add_address_hint", "peer":joiner_peer,
            "address":joiner_address.to_string()}),
        )
        .unwrap();
        let reverse_request = json!({"op":"discover_recovery_cutoff", "peer":joiner_peer,
            "revision":17, "topics":["streams/sample"]});
        assert_eq!(
            call(joiner, discover_request.clone()).unwrap()["state"],
            "recovery_cutoff_pending"
        );
        assert_eq!(
            call(admin, reverse_request.clone()).unwrap()["state"],
            "recovery_cutoff_pending"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        let mut completed = BTreeMap::new();
        while completed.len() < 2 {
            for handle in [admin, joiner] {
                call(handle, json!({"op":"poll_admission"})).unwrap();
                let result = call(handle, json!({"op":"poll_recovery_cutoff"})).unwrap();
                if result != Value::Null {
                    assert_eq!(result["state"], "recovery_cutoff_observed");
                    assert!(completed.insert(handle, result).is_none());
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "crossed cutoff deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(completed[&admin]["head"], 1);
        assert_eq!(completed[&joiner]["head"], 3);
        for invalid in [
            json!({"op":"discover_recovery_cutoff", "peer":vec![99;32], "revision":17, "topics":["streams/sample"]}),
            json!({"op":"discover_recovery_cutoff", "peer":peer, "revision":16, "topics":["streams/sample"]}),
            json!({"op":"discover_recovery_cutoff", "peer":peer, "revision":17, "topics":["streams/other"]}),
            json!({"op":"discover_recovery_cutoff", "peer":peer, "revision":17, "topics":["streams/sample","streams/sample"]}),
            json!({"op":"discover_recovery_cutoff", "peer":peer, "revision":17, "topics":[]}),
            json!({"op":"discover_recovery_cutoff", "peer":peer, "revision":17, "topics":["streams/sample"], "nonce":vec![1;32]}),
        ] {
            assert!(call(joiner, invalid).is_err());
        }
        assert_eq!(
            call(admin, json!({"op":"poll_admission"})).unwrap(),
            Value::Null
        );

        {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let reader = guard.as_ref().unwrap().workspace.as_ref().unwrap();
            assert_eq!(
                arachne_delivery::wire::verify_cutoff_reply(reader, &cutoff, &cutoff_reply)
                    .unwrap(),
                Some(3)
            );
            let mut next_request = cutoff.clone();
            next_request.nonce[0] ^= 1;
            assert!(
                arachne_delivery::wire::verify_cutoff_reply(reader, &next_request, &cutoff_reply)
                    .is_err()
            );
        }
        assert_eq!(
            exchange(b"DFCQ\x02".to_vec()),
            arachne_delivery::wire::denied_reply()
        );
        let reply = exchange(query.to_wire().unwrap());
        {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let reader = guard.as_ref().unwrap().workspace.as_ref().unwrap();
            let arachne_delivery::wire::RangeReply::Offered(range) =
                arachne_delivery::wire::verify_reply(reader, &query, &reply).unwrap()
            else {
                panic!("expected wire recovery offer")
            };
            assert_eq!(range.packets().len(), 1);
            assert_eq!(range.packets()[0].ciphertext, retained);
            assert_eq!(range.packets()[0].context.id, [12; 16]);
        }
        let fetch_request = json!({"op":"fetch_recovery_range", "peer":peer, "revision":17,
            "topics":["streams/sample"], "after":1, "through":2});
        assert_eq!(
            call(joiner, fetch_request.clone()).unwrap()["state"],
            "recovery_range_pending"
        );
        assert!(call(joiner, fetch_request.clone()).is_err());
        assert!(call(joiner, discover_request.clone()).is_err());
        poll_recovery();
        let ready = poll_range(joiner).unwrap();
        assert_eq!(ready["state"], "recovery_range_ready");
        assert_eq!(ready["packet_count"], 1);
        assert_eq!(ready["accepted_progress"], false);
        assert!(ready.get("payload").is_none() && ready.get("snapshot").is_none());
        {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let owner = guard.as_ref().unwrap();
            let ready = owner.ready_range.as_ref().unwrap();
            let arachne_delivery::wire::RangeReply::Offered(range) =
                arachne_delivery::wire::verify_reply(
                    owner.workspace.as_ref().unwrap(),
                    &ready.query,
                    &ready.reply,
                )
                .unwrap()
            else {
                panic!("expected retained verified range")
            };
            assert_eq!(range.packets()[0].ciphertext, retained);
            assert_eq!(range.packets()[0].context.id, [12; 16]);
        }
        assert_eq!(
            call(joiner, json!({"op":"poll_recovery_range"})).unwrap(),
            Value::Null
        );
        assert!(call(joiner, fetch_request.clone()).is_err());
        call(joiner, json!({"op":"cancel_recovery_range"})).unwrap();
        for invalid in [
            json!({"op":"fetch_recovery_range", "peer":peer, "revision":17,"topics":["streams/sample"],"after":2,"through":2}),
            json!({"op":"fetch_recovery_range", "peer":peer, "revision":16,"topics":["streams/sample"],"after":1,"through":2}),
            json!({"op":"fetch_recovery_range", "peer":vec![99;32], "revision":17,"topics":["streams/sample"],"after":1,"through":2}),
            json!({"op":"fetch_recovery_range", "peer":peer, "revision":17,"topics":["streams/sample","streams/sample"],"after":1,"through":2}),
        ] {
            assert!(call(joiner, invalid).is_err());
        }
        assert_eq!(
            call(admin, json!({"op":"poll_admission"})).unwrap(),
            Value::Null
        );
        let mut stale = arachne_delivery::RangeQuery::from_wire(&query.to_wire().unwrap()).unwrap();
        stale.policy_revision = 16;
        assert_eq!(
            exchange(stale.to_wire().unwrap()),
            arachne_delivery::wire::denied_reply()
        );
        assert_eq!(
            exchange(b"DFRQ\x02".to_vec()),
            arachne_delivery::wire::denied_reply()
        );
        call(
            admin,
            json!({"op":"install_member_policy","revision":18,"topics":["streams/other"]}),
        )
        .unwrap();
        assert_eq!(
            exchange(query.to_wire().unwrap()),
            arachne_delivery::wire::denied_reply()
        );
        assert_eq!(
            exchange(cutoff.to_wire().unwrap()),
            arachne_delivery::wire::denied_reply()
        );
        let mut revoked_cutoff = cutoff.clone();
        revoked_cutoff.policy_revision = 18;
        assert_eq!(
            exchange(revoked_cutoff.to_wire().unwrap()),
            arachne_delivery::wire::denied_reply()
        );
        call(joiner, fetch_request.clone()).unwrap();
        poll_recovery();
        let rejected = poll_range(joiner).unwrap();
        assert_eq!(rejected["state"], "recovery_range_rejected");
        assert_eq!(rejected["reason"], "Denied");
        assert!(
            session(joiner)
                .unwrap()
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ready_range
                .is_none()
        );
        // Receiver still has revision 17; current publisher policy denies it.
        call(joiner, discover_request.clone()).unwrap();
        poll_recovery();
        let denied = poll_cutoff(joiner).unwrap();
        assert_eq!(denied["state"], "recovery_cutoff_denied");
        assert!(denied.get("head").is_none());
        stale.policy_revision = 18;
        assert_eq!(
            exchange(stale.to_wire().unwrap()),
            arachne_delivery::wire::denied_reply()
        );
        // An authorized topic with no publications in this retained range still
        // receives signed coverage through normal dispatch over real Iroh.
        stale.topics = BTreeSet::from([Topic::new("streams/other").unwrap()]);
        let empty_reply = exchange(stale.to_wire().unwrap());
        {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let reader = guard.as_ref().unwrap().workspace.as_ref().unwrap();
            let arachne_delivery::wire::RangeReply::Offered(range) =
                arachne_delivery::wire::verify_reply(reader, &stale, &empty_reply).unwrap()
            else {
                panic!("expected signed empty recovery offer")
            };
            assert!(range.packets().is_empty());
        }
        assert_eq!(
            call(admin, json!({"op":"poll_admission"})).unwrap(),
            Value::Null
        );
        // A response requested under old local authority cannot be exposed after
        // policy advances, even if the remote signature itself remains valid.
        call(joiner, discover_request.clone()).unwrap();
        poll_recovery();
        call(
            joiner,
            json!({"op":"install_member_policy", "revision":18, "topics":["streams/other"]}),
        )
        .unwrap();
        assert!(poll_cutoff(joiner).is_err());
        assert_eq!(
            call(joiner, json!({"op":"poll_recovery_cutoff"})).unwrap(),
            Value::Null
        );
        let empty_request = json!({"op":"fetch_recovery_range", "peer":peer, "revision":18,
            "topics":["streams/other"], "after":1, "through":2});
        call(joiner, empty_request.clone()).unwrap();
        poll_recovery();
        let empty = poll_range(joiner).unwrap();
        assert_eq!(empty["state"], "recovery_range_ready");
        assert_eq!(empty["packet_count"], 0);
        call(joiner, json!({"op":"cancel_recovery_range"})).unwrap();
        call(joiner, empty_request.clone()).unwrap();
        poll_recovery();
        call(
            joiner,
            json!({"op":"install_member_policy", "revision":19, "topics":["streams/other"]}),
        )
        .unwrap();
        assert!(poll_range(joiner).is_err());
        assert!(
            session(joiner)
                .unwrap()
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .ready_range
                .is_none()
        );
        let mut cancelled_request = empty_request;
        cancelled_request["revision"] = json!(19);
        call(joiner, cancelled_request).unwrap();
        let aborted_range = {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            guard
                .as_ref()
                .unwrap()
                .range
                .as_ref()
                .unwrap()
                .task
                .abort_handle()
        };
        call(joiner, json!({"op":"cancel_recovery_range"})).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !aborted_range.is_finished() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        // Recovery actually decrypts a publication missed by this receiver. The
        // selected topic has no earlier traffic, so prior live ratchet use does
        // not masquerade as successful catch-up of already consumed packets.
        call(
            admin,
            json!({"op":"install_member_policy", "revision":19,
            "topics":["streams/other"]}),
        )
        .unwrap();
        for id in 90..97 {
            let missed = call(
                admin,
                json!({"op":"stage_network_publication", "revision":19,
                "topic":"streams/other", "id":vec![id;16], "payload":[id]}),
            )
            .unwrap();
            call(
                admin,
                json!({"op":"adopt_publication", "snapshot":missed["snapshot"]}),
            )
            .unwrap();
        }
        let head = {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            guard.as_ref().unwrap().publisher.as_ref().unwrap().head()
        };
        let recover = json!({"op":"fetch_recovery_range", "peer":peer, "revision":19,
            "topics":["streams/other"], "after":0, "through":head});
        call(joiner, recover.clone()).unwrap();
        // A newer live application is queued while the range request is pending.
        // Decrypting it now could discard the keys for the first missed records.
        call(
            joiner,
            json!({"op":"subscribe", "workspace":created["workspace"],
            "revision":19, "topic":"streams/other"}),
        )
        .unwrap();
        let live = call(
            admin,
            json!({"op":"stage_network_publication", "revision":19,
            "topic":"streams/other", "id":vec![107;16], "payload":[8]}),
        )
        .unwrap();
        call(
            admin,
            json!({"op":"adopt_publication", "snapshot":live["snapshot"]}),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let shared = session(joiner).unwrap();
            if !shared.lock().unwrap().as_ref().unwrap().receiver.is_empty() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "newer live packet was not queued"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            call(joiner, json!({"op":"poll_protected"}))
                .unwrap()
                .is_null(),
            "live reception must wait for pending recovery"
        );
        assert_eq!(
            call(
                joiner,
                json!({"op":"stage_reception", "context":[], "ciphertext":[]})
            )
            .unwrap_err(),
            "recovery must finish before live reception"
        );

        poll_recovery();
        assert_eq!(poll_range(joiner).unwrap()["packet_count"], 7);
        assert_eq!(
            call(joiner, json!({"op":"poll_recovered_publication"})).unwrap(),
            Value::Null
        );
        assert!(
            call(joiner, json!({"op":"poll_protected"}))
                .unwrap()
                .is_null(),
            "live reception must wait for ready recovery"
        );
        let [metadata, recovery_snapshot] =
            execute_stored(joiner, br#"{"op":"stage_recovery_range"}"#, &[]).unwrap();
        let metadata: Value = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(metadata["state"], "awaiting_recovery_save");
        assert_eq!(metadata["publication_count"], 7);
        assert!(metadata.get("payload").is_none() && metadata.get("snapshot").is_none());
        assert!(call(joiner, json!({"op":"poll_recovered_publication"})).is_err());
        assert!(
            execute_stored(joiner, br#"{"op":"adopt_reception"}"#, &recovery_snapshot).is_err()
        );
        let mut corrupt = recovery_snapshot.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(execute_stored(joiner, br#"{"op":"adopt_recovery"}"#, &corrupt).is_err());
        {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            assert!(guard.as_ref().unwrap().received.is_none());
        }
        let adopted =
            execute_stored(joiner, br#"{"op":"adopt_recovery"}"#, &recovery_snapshot).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&adopted[0]).unwrap()["publication_count"],
            7
        );
        assert!(call(joiner, json!({"op":"seal_workspace"})).is_err());
        for id in 90..97 {
            let recovered = call(joiner, json!({"op":"poll_recovered_publication"})).unwrap();
            assert_eq!(recovered["payload"], json!([id]));
            assert_eq!(recovered["id"], json!(vec![id; 16]));
            assert_eq!(recovered["topic"], "streams/other");
        }
        assert_eq!(
            call(joiner, json!({"op":"poll_recovered_publication"})).unwrap(),
            Value::Null
        );
        assert!(execute_stored(joiner, br#"{"op":"adopt_recovery"}"#, &recovery_snapshot).is_err());
        call(joiner, recover.clone()).unwrap();
        poll_recovery();
        poll_range(joiner).unwrap();
        assert_eq!(
            call(joiner, json!({"op":"stage_recovery_range"})).unwrap()["state"],
            "recovery_already_covered"
        );
        // Ordinary outgoing traffic must preserve the newly adopted receive state.
        let outgoing = call(
            joiner,
            json!({"op":"stage_network_publication", "revision":19,
            "topic":"streams/other", "id":vec![91;16], "payload":[7]}),
        )
        .unwrap();
        call(
            joiner,
            json!({"op":"adopt_publication", "snapshot":outgoing["snapshot"]}),
        )
        .unwrap();
        let live = poll_result(joiner, "poll_protected").unwrap();
        assert!(live.get("payload").is_none());
        let live = call(
            joiner,
            json!({"op":"adopt_reception", "snapshot":live["snapshot"]}),
        )
        .unwrap();
        assert_eq!(live["payload"], json!([8]));
        let mut continuation = recover;
        continuation["after"] = json!(head);
        continuation["through"] = json!(head + 1);
        call(joiner, continuation).unwrap();
        poll_recovery();
        poll_range(joiner).unwrap();
        let [metadata, snapshot] =
            execute_stored(joiner, br#"{"op":"stage_recovery_range"}"#, &[]).unwrap();
        let metadata: Value = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(metadata["publication_count"], 0);
        assert_eq!(metadata["already_received"], 1);
        execute_stored(joiner, br#"{"op":"adopt_recovery"}"#, &snapshot).unwrap();
        let [_, durable] = execute_stored(joiner, br#"{"op":"seal_workspace"}"#, &[]).unwrap();
        let journal_before = {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            guard
                .as_ref()
                .unwrap()
                .received
                .as_ref()
                .unwrap()
                .snapshot()
        };
        let mut pending_on_close = discover_request;
        pending_on_close["revision"] = json!(19);
        pending_on_close["topics"] = json!(["streams/other"]);
        call(joiner, pending_on_close).unwrap();
        let task = {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            guard
                .as_ref()
                .unwrap()
                .cutoff
                .as_ref()
                .unwrap()
                .task
                .abort_handle()
        };
        close(joiner).unwrap();
        assert!(task.is_finished());
        let restored = create(Some(&[42; 32])).unwrap();
        execute_stored(
            restored,
            &serde_json::to_vec(&json!({"op":"restore_workspace",
            "workspace":created["workspace"]}))
            .unwrap(),
            &durable,
        )
        .unwrap();
        {
            let shared = session(restored).unwrap();
            let guard = shared.lock().unwrap();
            let session = guard.as_ref().unwrap();
            assert_eq!(
                session.received.as_ref().unwrap().snapshot(),
                journal_before
            );
            let selection = BTreeSet::from([Topic::new("streams/other").unwrap()]);
            let author = session
                .workspace
                .as_ref()
                .unwrap()
                .member_id_for_endpoint(peer)
                .unwrap();
            assert_eq!(
                session
                    .received
                    .as_ref()
                    .unwrap()
                    .progress(author, &selection),
                Some(head + 1)
            );
            assert!(session.publisher.as_ref().unwrap().head() > 0);
        }
        assert_eq!(
            call(restored, json!({"op":"poll_recovered_publication"})).unwrap(),
            Value::Null
        );
        // Compose signed-object delivery with real native/Iroh lifecycle. Keep
        // legacy receipts and publisher history; do not reset saved workspaces.
        for handle in [admin, restored] {
            let staged = call(handle, json!({"op":"enable_object_delivery"})).unwrap();
            assert!(staged.get("payload").is_none());
            assert!(call(handle, json!({"op":"poll_pending_object"})).is_err());
            call(
                handle,
                json!({"op":"adopt_reception", "snapshot":staged["snapshot"]}),
            )
            .unwrap();
            if handle == admin {
                call(
                handle,
                json!({"op":"install_member_policy", "revision":20,"topics":["streams/objects"]}),
            )
            .unwrap();
            }
        }
        let send_object = |number: u8| {
            let staged = call(
                admin,
                json!({"op":"stage_network_publication", "revision":20,
                "topic":"streams/objects", "id":vec![number;16], "payload":[number]}),
            )
            .unwrap();
            call(
                admin,
                json!({"op":"adopt_publication", "snapshot":staged["snapshot"]}),
            )
            .unwrap()
        };
        let current = call(
            admin,
            json!({"op":"stage_network_publication", "revision":20,
                "topic":"streams/objects", "id":vec![100;16], "payload":[100],
                "current":{"selector":vec![7;32], "replacement_key":vec![8;32],
                    "expires_at":u64::MAX}}),
        )
        .unwrap();
        call(
            admin,
            json!({"op":"adopt_publication", "snapshot":current["snapshot"]}),
        )
        .unwrap();
        let missed = send_object(101);
        let after = missed["sequence"].as_u64().unwrap() - 1;
        let connect_objects = |handle| {
            call(
                handle,
                json!({"op":"add_address_hint","peer":peer,"address":address.to_string()}),
            )
            .unwrap();
            call(
                handle,
                json!({"op":"install_member_policy", "revision":20,"topics":["streams/objects"]}),
            )
            .unwrap();
            call(handle, json!({"op":"subscribe", "workspace":created["workspace"],"revision":20,"topic":"streams/objects"})).unwrap();
        };
        connect_objects(restored);
        let live = send_object(102);
        assert_eq!(live["admission"]["queued"], true);
        let staged = poll_result(restored, "poll_protected").unwrap();
        assert!(staged.get("payload").is_none());
        call(
            restored,
            json!({"op":"adopt_reception", "snapshot":staged["snapshot"]}),
        )
        .unwrap();
        let pending = call(restored, json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(pending["payload"], json!([102]));
        assert_eq!(
            call(restored, json!({"op":"poll_pending_object"})).unwrap(),
            pending
        );
        let [_, pending_snapshot] =
            execute_stored(restored, br#"{"op":"seal_workspace"}"#, &[]).unwrap();
        close(restored).unwrap();
        let restored = create(Some(&[42; 32])).unwrap();
        execute_stored(
            restored,
            &serde_json::to_vec(
                &json!({"op":"restore_workspace","workspace":created["workspace"]}),
            )
            .unwrap(),
            &pending_snapshot,
        )
        .unwrap();
        assert_eq!(
            call(restored, json!({"op":"poll_pending_object"})).unwrap(),
            pending
        );
        {
            let shared = session(restored).unwrap();
            let guard = shared.lock().unwrap();
            assert_eq!(
                guard
                    .as_ref()
                    .unwrap()
                    .received
                    .as_ref()
                    .unwrap()
                    .snapshot(),
                journal_before
            );
        }
        let ack = |handle, pending: &Value| {
            let request = json!({"op":"stage_object_acknowledgement", "member":pending["member"],
                "topic":pending["topic"], "id":pending["id"], "counter":pending["counter"]});
            let mut wrong = request.clone();
            wrong["id"] = json!(vec![0; 16]);
            assert!(call(handle, wrong).is_err());
            let staged = call(handle, request).unwrap();
            let snapshot: Vec<u8> = serde_json::from_value(staged["snapshot"].clone()).unwrap();
            assert_eq!(
                execute_stored(handle, br#"{"op":"adopt_publication"}"#, &snapshot).unwrap_err(),
                "wrong adoption lifecycle phase"
            );
            execute_stored(handle, br#"{"op":"adopt_reception"}"#, &snapshot).unwrap();
        };
        ack(restored, &pending);
        assert_eq!(
            call(restored, json!({"op":"poll_pending_object"})).unwrap(),
            Value::Null
        );
        connect_objects(restored);
        let next = call(restored, json!({"op":"next_membership_peer"})).unwrap();
        assert_eq!(next["peer"], json!(peer));
        let authority = next["member"].clone();
        call(
            restored,
            json!({"op":"fetch_current_view", "authority":authority,
                "revision":20, "topic":"streams/objects", "selector":vec![7;32]}),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let ready = loop {
            let response = call(admin, json!({"op":"poll_admission"})).unwrap();
            assert!(response.is_null() || response["state"] == "current_view_replied");
            let response = call(restored, json!({"op":"poll_current_view"})).unwrap();
            if !response.is_null() {
                break response;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "current-view control deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(ready["state"], "current_view_ready");
        assert_eq!(ready["automatic_source"], true);
        assert_eq!(ready["cut"], 1);
        assert_eq!(ready["value_count"], 1);
        let staged = call(restored, json!({"op":"stage_current_view"})).unwrap();
        assert_eq!(staged["state"], "awaiting_current_view_save");
        assert_eq!(staged["pending"], 1);
        assert!(call(restored, json!({"op":"poll_pending_object"})).is_err());
        call(
            restored,
            json!({"op":"adopt_current_view", "snapshot":staged["snapshot"]}),
        )
        .unwrap();
        let current = call(restored, json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(current["payload"], json!([100]));
        assert_eq!(current["current"]["replacement_key"], json!(vec![8; 32]));
        ack(restored, &current);
        call(
            restored,
            json!({"op":"fetch_recovery_range", "peer":peer, "revision":20,
            "topics":["streams/objects"], "after":after, "through":live["sequence"]}),
        )
        .unwrap();
        poll_recovery();
        poll_range(restored).unwrap();
        let [metadata, snapshot] =
            execute_stored(restored, br#"{"op":"stage_recovery_range"}"#, &[]).unwrap();
        let metadata: Value = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(metadata["publication_count"], 1); // live object already acknowledged
        execute_stored(restored, br#"{"op":"adopt_recovery"}"#, &snapshot).unwrap();
        let recovered = call(restored, json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(recovered["payload"], json!([101]));
        ack(restored, &recovered);
        let [_, snapshot] = execute_stored(restored, br#"{"op":"seal_workspace"}"#, &[]).unwrap();
        close(restored).unwrap();
        let restored = create(Some(&[42; 32])).unwrap();
        execute_stored(
            restored,
            &serde_json::to_vec(
                &json!({"op":"restore_workspace","workspace":created["workspace"]}),
            )
            .unwrap(),
            &snapshot,
        )
        .unwrap();
        assert_eq!(
            call(restored, json!({"op":"poll_pending_object"})).unwrap(),
            Value::Null
        );
        connect_objects(restored);
        call(
            restored,
            json!({"op":"fetch_recovery_range", "peer":peer,"revision":20,
            "topics":["streams/objects"],"after":after,"through":live["sequence"]}),
        )
        .unwrap();
        poll_recovery();
        poll_range(restored).unwrap();
        assert_eq!(
            call(restored, json!({"op":"stage_recovery_range"})).unwrap()["state"],
            "recovery_no_new_objects"
        );
        let current_live = call(
            admin,
            json!({"op":"stage_network_publication", "revision":20,
                "topic":"streams/objects", "id":vec![109;16], "payload":[109],
                "current":{"selector":vec![7;32], "replacement_key":vec![8;32],
                    "expires_at":u64::MAX}}),
        )
        .unwrap();
        call(
            admin,
            json!({"op":"adopt_publication", "snapshot":current_live["snapshot"]}),
        )
        .unwrap();
        let staged = poll_result(restored, "poll_protected").unwrap();
        call(
            restored,
            json!({"op":"adopt_reception", "snapshot":staged["snapshot"]}),
        )
        .unwrap();
        let current_pending = call(restored, json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(current_pending["payload"], json!([109]));
        assert_eq!(current_pending["current"]["selector"], json!(vec![7; 32]));
        assert_eq!(
            current_pending["current"]["replacement_key"],
            json!(vec![8; 32])
        );
        ack(restored, &current_pending);
        for number in 110..150 {
            send_object(number);
        }
        call(restored, json!({"op":"discover_recovery_cutoff", "peer":peer,"revision":20,"topics":["streams/objects"]})).unwrap();
        poll_recovery();
        let window = poll_cutoff(restored).unwrap();
        assert!(window["retained_after"].as_u64().unwrap() > after);
        assert_eq!(window["accepted_through"], 0);
        call(restored, json!({"op":"fetch_recovery_range", "peer":peer,"revision":20,
            "topics":["streams/objects"],"after":window["retained_after"],"through":window["head"]})).unwrap();
        poll_recovery();
        poll_range(restored).unwrap();
        let [metadata, snapshot] =
            execute_stored(restored, br#"{"op":"stage_recovery_range"}"#, &[]).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&metadata).unwrap()["publication_count"],
            32
        );
        execute_stored(restored, br#"{"op":"adopt_recovery"}"#, &snapshot).unwrap();
        let service = create(Some(&[43; 32])).unwrap();
        let invite = call(admin, json!({"op":"issue_invitation"})).unwrap();
        let pending_service = call(
            service,
            json!({"op":"begin_join", "invitation":invite["invitation"],
            "checkpoint":invite["checkpoint"], "display_name":"Air traffic feed"}),
        )
        .unwrap();
        let admission = json!({"op":"stage_admission", "authenticated_endpoint":pending_service["endpoint"],
            "request":pending_service["admission_request"]});
        let [_, saved] =
            execute_stored(admin, &serde_json::to_vec(&admission).unwrap(), &[]).unwrap();
        execute_stored(admin, br#"{"op":"adopt_admission"}"#, &saved).unwrap();
        let response = call(
            admin,
            json!({"op":"retained_admission", "authenticated_endpoint":pending_service["endpoint"],
            "request":pending_service["admission_request"]}),
        )
        .unwrap();
        let step = json!({"commit":response["commit"], "authorization":response["authorization"]});
        call(
            restored,
            json!({"op":"fetch_membership_update", "peer":peer}),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let fetched = loop {
            call(admin, json!({"op":"poll_admission"})).unwrap();
            let result = call(restored, json!({"op":"poll_membership_update"})).unwrap();
            if result != Value::Null {
                break result;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "membership query deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(fetched["state"], "membership_update_available");
        assert_eq!(fetched["step"], step);
        assert!(fetched.get("welcome").is_none());
        let update = json!({"op":"stage_admission_update", "step":fetched["step"]});
        assert_eq!(
            call(restored, update.clone()).unwrap_err(),
            "pending application delivery must be acknowledged before membership update"
        );
        assert_eq!(
            call(restored, admission).unwrap_err(),
            "pending application delivery must be acknowledged before membership update"
        );
        for number in 118..150 {
            let pending = call(restored, json!({"op":"poll_pending_object"})).unwrap();
            assert_eq!(pending["payload"], json!([number]));
            ack(restored, &pending);
        }
        println!(
            "NATIVE_OBJECT_INBOX legacy_preserved=true live_pending_restart=true acknowledgement_restart=true missed_recovery=true adapter_callback=not_exercised"
        );
        let [_, saved] =
            execute_stored(restored, &serde_json::to_vec(&update).unwrap(), &[]).unwrap();
        let mut altered = saved.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(execute_stored(restored, br#"{"op":"adopt_admission"}"#, &altered).is_err());
        assert!(execute_stored(restored, br#"{"op":"adopt_reception"}"#, &saved).is_err());
        close(restored).unwrap(); // Saved candidate survives before explicit adoption.
        let restored = create(Some(&[42; 32])).unwrap();
        let [metadata, _] = execute_stored(
            restored,
            &serde_json::to_vec(
                &json!({"op":"restore_workspace", "workspace":created["workspace"]}),
            )
            .unwrap(),
            &saved,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&metadata).unwrap()["members"],
            3
        );
        assert!(call(restored, update).is_err()); // replay
        let [_, saved] = execute_stored(
            service,
            &serde_json::to_vec(
                &json!({"op":"stage_join", "commits":[step], "welcome":response["welcome"]}),
            )
            .unwrap(),
            &[],
        )
        .unwrap();
        let [metadata, _] = execute_stored(service, br#"{"op":"adopt_join"}"#, &saved).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&metadata).unwrap()["members"],
            3
        );
        close(service).unwrap();
        close(restored).unwrap();
        close(admin).unwrap();
    }
}
