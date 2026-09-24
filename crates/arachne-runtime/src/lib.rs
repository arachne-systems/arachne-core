//! Portable blocking Arachne session runtime shared by native clients and language bindings.
//! No membership API is implied by creating an authenticated transport endpoint.
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Arc, Mutex,
    },
    time::Duration,
};

use arachne_node::{
    AdmissionReport, Node, Timeouts, Topic,
};
use serde_json::{Value, json};
use tokio::{
    runtime::Runtime,
};

mod client;
mod committed_view;
mod errors;
mod json;
mod ops;
mod registry;
mod session;
pub use registry::{
    cancel, close, create, create_lan, create_nearby, create_relay, create_relay_with_options,
    create_wan, create_wan_only, create_with_options, describe, wait_for_work,
};
#[cfg(feature = "tor")]
pub use registry::create_tor;
use registry::{
    DEVICE_OVERLAY_PATHS, MAX_DEVICE_OVERLAY_PATHS, release_overlay_paths,
    reserve_overlay_paths, session, shutdown_session,
};
use ops::recovery::{
    PendingCurrentView, PendingDirectRange, PendingRange, ReadyCurrentView, ReadyDirectRange,
    ReadyRange,
};
use ops::admission::{
    ADMISSION_HISTORY_PAGE_REQUEST, admission_packet, admission_reply_page,
    parse_admission_history_page_packet, pinned_checkpoint,
};
#[cfg(test)]
use ops::admission::retained_reply;
use ops::join::{
    INVITATION_CHECKPOINT_REQUEST, JoinLifecycle, PendingCheckpointExchange, PendingJoinExchange,
    invitation_checkpoint_page, pending_metadata,
};
use session::{
    carry_delivery, check_epoch_transition, commit_workspace, seal_state,
    transition_activity,
};
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

    /// The session workspace's gossip tag key, so a qualification harness can
    /// join raw nodes to the same overlay. The host already holds this state.
    pub fn gossip_tag_key(handle: i64) -> Result<[u8; 32], String> {
        let shared = crate::session(handle).map_err(crate::errors::text)?;
        let guard = shared.lock().map_err(|_| "node session unavailable")?;
        guard
            .as_ref()
            .ok_or("node is closed")?
            .workspace
            .as_ref()
            .ok_or("session has no workspace")?
            .gossip_tag_key()
            .map_err(str::to_owned)
    }
}
mod admission_waiters;
mod persistence;
pub(crate) mod presence;
mod resources;
mod work_signal;
mod workspace_activity;
pub use arachne_api::{ApiError, ErrorCode};
pub use client::{
    AdmissionApproval, AdmissionApprovalPage, AdmissionAuthorization, InvitationCheckpoint,
    InvitationControl, InvitationKind, MemberAction, NearbyAdvertisement, NearbyEndpoint,
    NearbyMode, NearbyScan, PresenceRound, RemovedMembership, AdmissionReply, Client, ClientConfig, ConnectivityReport,
    ConnectionCapacityMetrics, ControlTimingMetrics, DeliveryFailure, DeliveryReport,
    DurationSummary, EndpointInfo, Error, ErrorKind, InterestObservation, InvitationDetails,
    InvitationInfo, JoinAdmissionStep, JoinRequest, MemberInfo, MemberKind,
    MembershipGossipMetrics, MemberRoster, Network, PeerPolicy, PeerRoute, Presence, Publication,
    PublicationCandidate, PublicationCurrent, ProtectedReceptionCandidate,
    ReceivedProtectedPublication, RecoveryAdoption, RecoveryCandidate, RecoveryRangeReady,
    RecoveryRangeRequest, RecoveryRangeStatus, RecoveryStage, Result as ClientResult, RouteHint,
    RouteKind, WorkspaceCandidate, WorkspaceInfo, WorkspaceMetrics, WorkspaceState,
};
pub use client::{OperatorRelay, RelayTrust, TransportInfo, TransportOptions, TransportTimeouts};
pub use arachne_store::FreshnessAnchor;
pub use persistence::{
    enable_record_storage, record_freshness, restore_record_storage,
    restore_record_storage_with_freshness, save_candidate,
};
pub use workspace_activity::{Activity as WorkspaceActivity, Phase as WorkspacePhase};
pub use errors::legacy_text;
pub use json::{
    MAX_REQUEST, MAX_STORED_SNAPSHOT, execute, execute_stored, execute_stored_with_code,
    execute_with_code, inspect_invitation,
};


enum WorkspaceTransition {
    RoutedPublication(
        arachne_routing::PublicationContext,
        arachne_node::DeliveryClass,
        Vec<u8>,
        Vec<[u8; 32]>,
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
}

struct StagedWorkspace {
    publisher: Option<arachne_delivery::PublisherLog>,
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

/// The transport services this endpoint was bound with, for `describe`.
#[derive(Clone, Copy)]
struct TransportSummary {
    public_lookup: bool,
    operator_relay: bool,
    timeouts: Timeouts,
}

/// One endpoint session. Each subsystem owns its state in its own struct.
struct Session {
    // Transport and runtime.
    node: Node,
    receiver: arachne_node::MessageReceiver,
    runtime: Runtime,
    overlay_paths: usize,
    // Committed workspace and durable state.
    /// The committed workspace. Shared and never edited in place: a transition
    /// works on a provisional copy, and `commit_workspace` replaces this.
    workspace: Option<Arc<arachne_security::Workspace>>,
    /// The same state, published for inquiries answered without the host.
    committed: committed_view::Published,
    activity: WorkspaceActivity,
    storage_key: Option<arachne_security::StorageKey>,
    records: Option<persistence::NativeStore>,
    // Subsystems.
    transition: TransitionState,
    delivery: DeliveryState,
    admission: AdmissionState,
    join: JoinState,
    membership: MembershipState,
    recovery: RecoveryState,
    nearby: NearbyState,
    resources: resources::Jobs,
    presence: presence::Presence,
    interests: interest::Updates,
    /// Set by an op that ended the session (a removal was adopted or
    /// restored). `ops::run` then takes the session and shuts it down.
    ending: bool,
}

/// The one staged transition and the one inbound exchange that waits for it.
#[derive(Default)]
struct TransitionState {
    /// A staged workspace candidate that awaits durable adoption.
    staged: Option<StagedWorkspace>,
    /// A staged removal (this member left or was removed) and its token.
    removal: Option<(arachne_security::RemovedMembership, Vec<u8>)>,
    /// A received control request (admission, leave, offer) that waits for
    /// the staged transition before it is answered.
    inbound: Option<arachne_node::ControlRequest>,
}

/// Object delivery state of the committed workspace.
#[derive(Default)]
struct DeliveryState {
    publisher: Option<arachne_delivery::PublisherLog>,
    inbox: Option<arachne_delivery::inbox::ObjectInbox>,
}

/// Owner-side admission intake.
struct AdmissionState {
    queue: arachne_security::AdmissionQueue,
    metadata: BTreeMap<[u8; 32], QueuedAdmission>,
    waiters: admission_waiters::AdmissionWaiters<arachne_node::ControlRequest>,
    pushes: Vec<PendingControl<[u8; 32]>>,
    pending_approvals: BTreeMap<[u8; 32], PendingAdmissionApproval>,
    staged_approval_id: Option<[u8; 32]>,
    // The bounded set of queued membership transitions handed to the durable
    // stage/adopt boundary; retained replies remain independently retryable.
    in_flight: Vec<arachne_security::AdmissionAttempt>,
    // Forced-progress trigger for batch staging: admission packets read since
    // the last staging attempt. Duplicate retries can keep the inbox non-empty
    // for ever; a count of reads ends that without waiting on a clock.
    reads_since_stage: usize,
}

impl Default for AdmissionState {
    fn default() -> Self {
        Self {
            queue: arachne_security::AdmissionQueue::new(),
            metadata: BTreeMap::new(),
            waiters: admission_waiters::AdmissionWaiters::new(MAX_ADMISSION_WAITERS),
            pushes: Vec::new(),
            pending_approvals: BTreeMap::new(),
            staged_approval_id: None,
            in_flight: Vec::new(),
            reads_since_stage: 0,
        }
    }
}

/// Joiner-side state of one pending join.
#[derive(Default)]
struct JoinState {
    pending: Option<arachne_security::PendingJoin>,
    lifecycle: Option<JoinLifecycle>,
    checkpoint_exchange: Option<PendingCheckpointExchange>,
    exchange: Option<PendingJoinExchange>,
    /// History this session already fetched for the pending join, beyond the
    /// last rollover boundary the host still carries. Untrusted until
    /// `StageJoin` replays it through the verifier from the pinned checkpoint.
    history_prefix: Vec<Value>,
}

/// Membership reconciliation: queries, offers, gossip and profiles.
struct MembershipState {
    update: Option<PendingControl<membership::StateBasis>>,
    offer: Option<PendingControl<u64>>,
    offer_requires_adoption: bool,
    /// Last failed membership query per peer, for the peer-choice cooldown.
    peer_failures: BTreeMap<[u8; 32], std::time::Instant>,
    /// The staged candidate came from a peer's step, not a local commit.
    staged_step_received: bool,
    /// Gossiped steps that skip ahead of this node's epoch, keyed by the
    /// epoch they extend. Bounded; applied in order as earlier steps land.
    steps_ahead: BTreeMap<u64, Vec<u8>>,
    /// The newest epoch heard by gossip or presence, and members that have it.
    /// A hint only: the steps are pulled and verified.
    head: Option<(u64, Vec<[u8; 32]>)>,
    /// One range pull toward `head`, keyed by the epoch it extends.
    range_pull: Option<PendingControl<u64>>,
    /// Membership gossip outcomes, for workspace_metrics.
    gossip_counts: Arc<membership::GossipCounts>,
    /// One page pull of a peer's retained names, and the peer sets already
    /// walked to the end (peer -> its profile digest), bounded.
    profile_pull: Option<PendingControl<membership::ProfilePull>>,
    profiles_walked: BTreeMap<[u8; 32], [u8; 32]>,
    /// Gossiped profiles of members not yet in this roster (bounded).
    profiles_pending: VecDeque<Vec<u8>>,
    /// Retained member profiles, shared with the inquiry responder.
    profiles: membership::Profiles,
    peer_profile_summaries: BTreeMap<[u8; 32], [u8; 32]>,
}

impl MembershipState {
    fn new(profiles: membership::Profiles) -> Self {
        Self {
            update: None,
            offer: None,
            offer_requires_adoption: false,
            peer_failures: BTreeMap::new(),
            staged_step_received: false,
            steps_ahead: BTreeMap::new(),
            head: None,
            range_pull: None,
            gossip_counts: Arc::default(),
            profile_pull: None,
            profiles_walked: BTreeMap::new(),
            profiles_pending: VecDeque::new(),
            profiles,
            peer_profile_summaries: BTreeMap::new(),
        }
    }
}

/// Recovery, direct recovery and current-view repair jobs.
#[derive(Default)]
struct RecoveryState {
    cutoff: Option<PendingControl<arachne_delivery::wire::CutoffQuery>>,
    current_view: Option<PendingCurrentView>,
    ready_current_view: Option<ReadyCurrentView>,
    range: Option<PendingRange>,
    ready_range: Option<ReadyRange>,
    direct_range: Option<PendingDirectRange>,
    ready_direct_range: Option<ReadyDirectRange>,
    direct_miss: Option<arachne_delivery::wire::DirectRangeQuery>,
}

/// Device-level nearby advertisement.
#[derive(Default)]
struct NearbyState {
    workspaces: BTreeMap<[u8; 32], Vec<u8>>,
    identity: Option<String>,
}

impl Session {
    /// The one constructor: an empty session around a bound node.
    fn new(
        node: Node,
        receiver: arachne_node::MessageReceiver,
        runtime: Runtime,
        committed: committed_view::Published,
        storage_key: Option<arachne_security::StorageKey>,
        presence: presence::Presence,
    ) -> Self {
        let profiles = committed.profiles();
        Self {
            node,
            receiver,
            runtime,
            overlay_paths: 0,
            workspace: None,
            committed,
            activity: WorkspaceActivity::default(),
            storage_key,
            records: None,
            transition: TransitionState::default(),
            delivery: DeliveryState::default(),
            admission: AdmissionState::default(),
            join: JoinState::default(),
            membership: MembershipState::new(profiles),
            recovery: RecoveryState::default(),
            nearby: NearbyState::default(),
            resources: resources::Jobs::default(),
            presence,
            interests: interest::Updates::default(),
            ending: false,
        }
    }
}

const MAX_WORKSPACE_OVERLAY_PATHS: usize = 5;
// JSON commit/authorization arrays must fit both the 32 KiB membership offer
// request and the 128 KiB admission reply. The lower MLS seam supports 128;
// this transport adapter deliberately uses the smaller safe batch.
const MAX_RUNTIME_ADMISSION_BATCH: usize = 16;
// Half of the 512 control-exchange reserve (arachne-node budget.rs). Presence,
// profile and recovery exchanges always keep the other half.
const MAX_ADMISSION_WAITERS: usize = 256;

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


#[cfg(test)]
use membership::JoinStep;

fn report(value: AdmissionReport) -> DeliveryReport {
    DeliveryReport {
        admitted: value.admitted,
        queued: value.queued,
        failed: value
            .failed
            .into_iter()
            .map(|(peer, error)| DeliveryFailure {
                peer,
                error: error.to_string(),
            })
            .collect(),
    }
}

/// `report` as a JSON value, for replies that are still JSON.
fn report_value(value: AdmissionReport) -> Value {
    serde_json::to_value(report(value)).unwrap_or(Value::Null)
}

#[cfg(test)]
mod large_invitation_tests;

#[cfg(test)]
mod tests {
    use super::*;

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
            let (registered, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
            owner = registered.workspace;
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
            let mut reply = serde_json::to_value(
                retained_reply(&prepared.workspace, endpoint(20_000), &requests[0]).unwrap(),
            )
            .unwrap();
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
        let (registered, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
        owner = registered.workspace;
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
        let mut admin = Workspace::create([104; 32], "Publisher").unwrap();
        let (registered, invitation, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
        admin = registered.workspace;
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
            let object = sender
                .protect_object(context.topic.namespace().as_bytes(), &aad, b"pending")
                .unwrap();
            let InboxStage::Prepared(next) = inbox
                .stage_with_recipients(&reader, &context, &recipients, &object)
                .unwrap()
            else {
                panic!("object was not staged")
            };
            inbox = *next;
        }
        let publisher =
            PublisherLog::new(&reader).unwrap();
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
            // Pending application objects never block a membership step (A3).
            check_epoch_transition(locked.as_mut().unwrap()).unwrap();
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
            assert_eq!(owner.delivery.inbox.as_ref().unwrap().pending_count(), 1);
            check_epoch_transition(owner).unwrap();
        }
        close(handle).unwrap();
    }

    #[test]
    fn removal_is_not_delayed_by_pending_objects_and_delivery_state_carries() {
        use arachne_delivery::{
            PublisherLog,
            inbox::{InboxStage, ObjectInbox},
        };
        use arachne_routing::PublicationContext;
        use arachne_security::{PendingJoin, StorageKey, Workspace};

        let root = [105; 32];
        let handle = create(Some(&root)).unwrap();
        let call = |request: Value| -> Result<Value, String> {
            serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
                .map_err(|error| error.to_string())
        };
        let description: Value = serde_json::from_str(&describe(handle).unwrap()).unwrap();
        let endpoint = serde_json::from_value(description["endpoint_key"].clone()).unwrap();
        // The runtime session is the administrator; the sender is a member.
        let admin = Workspace::create(endpoint, "Admin").unwrap();
        let (registered, invitation, checkpoint) =
            admin.prepare_invitation(u64::MAX, false, false).unwrap();
        let admin = registered.workspace;
        let join =
            PendingJoin::from_invitation(&invitation, &checkpoint, [106; 32], "Sender").unwrap();
        let prepared = admin
            .prepare_admission([106; 32], join.admission_request().unwrap())
            .unwrap();
        let mut proof = join.join_proof().unwrap();
        proof
            .apply_add(&prepared.authorization, &prepared.commit)
            .unwrap();
        let mut sender = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
        let admin = prepared.workspace;
        let context = PublicationContext {
            workspace: admin.id(),
            revision: 7,
            topic: Topic::new("chat/messages").unwrap(),
            id: [3; 16],
            sequence: std::num::NonZeroU64::new(1),
        };
        let object = sender
            .protect_object(b"chat", &context.authenticated_bytes(), b"still pending")
            .unwrap();
        let InboxStage::Prepared(inbox) = ObjectInbox::new(admin.id(), admin.epoch())
            .stage(&admin, &context, &object)
            .unwrap()
        else {
            panic!("object was not staged")
        };
        let publisher = PublisherLog::new(&admin).unwrap();
        let key = StorageKey::derive(&root).unwrap();
        let snapshot = inbox.seal(&admin, &key, &publisher).unwrap();
        call(json!({"op":"restore_workspace","workspace":admin.id(),"snapshot":snapshot}))
            .unwrap();
        let pending = call(json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(pending["payload"], json!(b"still pending"));

        // The removal stages and adopts while the object is still pending.
        let staged = call(json!({"op":"stage_management",
            "action":{"kind":"remove","member":sender.member().unwrap().id()}}))
        .unwrap();
        let adopted =
            call(json!({"op":"adopt_admission","snapshot":staged["snapshot"]})).unwrap();
        assert_eq!(adopted["epoch"], admin.epoch() + 1);
        assert_eq!(adopted["members"], 1);
        // The pending object is carried into the new epoch and survives restart.
        assert_eq!(call(json!({"op":"poll_pending_object"})).unwrap(), pending);
        close(handle).unwrap();
        let handle = create(Some(&root)).unwrap();
        let call = |request: Value| -> Result<Value, String> {
            serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
                .map_err(|error| error.to_string())
        };
        call(json!({"op":"restore_workspace","workspace":admin.id(),
            "snapshot":staged["snapshot"]}))
        .unwrap();
        assert_eq!(call(json!({"op":"poll_pending_object"})).unwrap(), pending);
        let acknowledged = call(json!({"op":"stage_object_acknowledgement",
            "member":pending["member"], "topic":pending["topic"],
            "counter":pending["counter"], "id":pending["id"]}))
        .unwrap();
        call(json!({"op":"adopt_reception","snapshot":acknowledged["snapshot"]})).unwrap();
        assert!(call(json!({"op":"poll_pending_object"})).unwrap().is_null());
        // The removed member's objects are no longer accepted.
        let late = PublicationContext {
            id: [4; 16],
            sequence: std::num::NonZeroU64::new(2),
            ..context
        };
        let backdated = sender
            .protect_object(b"chat", &late.authenticated_bytes(), b"after removal")
            .unwrap();
        {
            let shared = session(handle).unwrap();
            let guard = shared.lock().unwrap();
            let session = guard.as_ref().unwrap();
            assert_eq!(
                session
                    .delivery.inbox
                    .as_ref()
                    .unwrap()
                    .stage(session.workspace.as_ref().unwrap(), &late, &backdated)
                    .err(),
                Some("object author not current")
            );
        }
        close(handle).unwrap();
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
        let issue_invitation = |handle: i64| -> Value {
            let staged = call(
                handle,
                json!({"op":"stage_invitation","personal":false,"expires_at":0}),
            )
            .unwrap();
            call(
                handle,
                json!({"op":"adopt_admission","snapshot":staged["snapshot"]}),
            )
            .unwrap()["issued_invitation"]
                .clone()
        };
        // Read the next pending inbox object and durably acknowledge it.
        let take_pending = |handle: i64| -> Value {
            let pending = call(handle, json!({"op":"poll_pending_object"})).unwrap();
            assert!(!pending.is_null(), "expected a pending object");
            let staged = call(
                handle,
                json!({"op":"stage_object_acknowledgement", "member":pending["member"],
                "topic":pending["topic"], "counter":pending["counter"], "id":pending["id"]}),
            )
            .unwrap();
            call(
                handle,
                json!({"op":"adopt_reception","snapshot":staged["snapshot"]}),
            )
            .unwrap();
            pending
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
        // The invitation must be registered before it is sealed as the
        // rollback target below, otherwise restoring to `old` would make the
        // admission look up a key that was never committed to policy.
        let invite = issue_invitation(admin);
        let old = call(admin, json!({"op":"seal_workspace"})).unwrap();
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
        // +1: registering the invitation now costs an epoch before the
        // admission commit that seated the second member.
        assert_eq!(restored["epoch"], 2);
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
        // The result is retained, so this request is an inquiry: the
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
                &vec![0; MAX_STORED_SNAPSHOT + 1]
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
            let log = guard.as_ref().unwrap().delivery.publisher.as_ref().unwrap();
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
        {
            let shared = session(joiner).unwrap();
            let guard = shared.lock().unwrap();
            let owner = guard.as_ref().unwrap().workspace.as_ref().unwrap();
            assert!(
                owner
                    .unprotect_object(
                        b"streams",
                        &tampered_context.authenticated_bytes(),
                        &ciphertext
                    )
                    .is_err()
            );
        }
        // The raw MLS application ops are gone; objects are the only path.
        for op in ["stage_publication", "stage_reception", "enable_object_delivery"] {
            assert!(call(joiner, json!({"op":op})).is_err());
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        let network_received = loop {
            let received = call(joiner, json!({"op":"poll_protected"})).unwrap();
            if !received.is_null() {
                break received;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(network_received.get("payload").is_none());
        assert_eq!(network_received["state"], "awaiting_reception_save");
        call(
            joiner,
            json!({"op":"adopt_reception","snapshot":network_received["snapshot"]}),
        )
        .unwrap();
        let delivered_network = take_pending(joiner);
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
        call(
            admin,
            json!({"op":"adopt_reception","snapshot":incoming["snapshot"]}),
        )
        .unwrap();
        let reverse_delivered = take_pending(admin);
        assert_eq!(reverse_delivered["payload"], json!([9]));
        assert_eq!(reverse_delivered["member"], pending["member"]["id"]);
        assert!(call(admin, json!({"op":"publish","workspace":created["workspace"],"revision":1,"topic":"sample","payload":[1]})).is_err());
        assert!(call(joiner, json!({"op":"poll"})).is_err());
        assert!(
            call(
                joiner,
                json!({"op":"adopt_reception","snapshot":staged_join["snapshot"]})
            )
            .is_err()
        );
        let [_, received] = execute_stored(joiner, br#"{"op":"seal_workspace"}"#, &[]).unwrap();
        close(joiner).unwrap();
        let joiner = create(Some(&[42; 32])).unwrap();
        execute_stored(
            joiner,
            &serde_json::to_vec(
                &json!({"op":"restore_workspace","workspace":created["workspace"]}),
            )
            .unwrap(),
            &received,
        )
        .unwrap();
        // The acknowledged object stays acknowledged after restore.
        assert!(call(joiner, json!({"op":"poll_pending_object"})).unwrap().is_null());
        // Simulate process ownership loss after candidate persistence but before
        // adoption. No filesystem/power-loss claim: the record is held in RAM.
        let request = serde_json::to_vec(&json!({"op":"stage_network_publication","revision":17,"topic":"streams/sample","id":vec![12;16],"payload":[7]})).unwrap();
        let candidate = execute_stored(admin, &request, &[]).unwrap();
        assert!(candidate[1].starts_with(b"DFWB\x01"));
        let (head, retained) = {
            let shared = session(admin).unwrap();
            let guard = shared.lock().unwrap();
            let session = guard.as_ref().unwrap();
            assert_eq!(session.delivery.publisher.as_ref().unwrap().head(), 1);
            let log = session
                .transition.staged
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
            let log = guard.as_ref().unwrap().delivery.publisher.as_ref().unwrap();
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
                .transition.staged
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
            let reader = guard
                .as_ref()
                .unwrap()
                .workspace
                .as_ref()
                .unwrap()
                .provisional_copy()
                .unwrap();
            for packet in packets {
                let context = packet.context.authenticated_bytes();
                // Objects carry no ratchet: decryption is repeatable and
                // side-effect free; the inbox suppresses replays.
                for _ in 0..2 {
                    assert_eq!(
                        reader
                            .unprotect_object(b"streams", &context, &packet.ciphertext)
                            .unwrap()
                            .message
                            .payload,
                        [7]
                    );
                }
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
            let ready = owner.recovery.ready_range.as_ref().unwrap();
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
                .recovery.ready_range
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
                .recovery.ready_range
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
                .recovery.range
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
            guard.as_ref().unwrap().delivery.publisher.as_ref().unwrap().head()
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
        poll_recovery();
        assert_eq!(poll_range(joiner).unwrap()["packet_count"], 7);
        let [metadata, recovery_snapshot] =
            execute_stored(joiner, br#"{"op":"stage_recovery_range"}"#, &[]).unwrap();
        let metadata: Value = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(metadata["state"], "awaiting_recovery_save");
        assert_eq!(metadata["publication_count"], 7);
        assert!(metadata.get("payload").is_none() && metadata.get("snapshot").is_none());
        assert!(
            execute_stored(joiner, br#"{"op":"adopt_reception"}"#, &recovery_snapshot).is_err()
        );
        let mut corrupt = recovery_snapshot.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(execute_stored(joiner, br#"{"op":"adopt_recovery"}"#, &corrupt).is_err());
        let adopted =
            execute_stored(joiner, br#"{"op":"adopt_recovery"}"#, &recovery_snapshot).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&adopted[0]).unwrap()["publication_count"],
            7
        );
        // Recovered objects wait in the durable inbox like live ones.
        for id in 90..97 {
            let recovered = take_pending(joiner);
            assert_eq!(recovered["payload"], json!([id]));
            assert_eq!(recovered["id"], json!(vec![id; 16]));
            assert_eq!(recovered["topic"], "streams/other");
        }
        assert!(call(joiner, json!({"op":"poll_pending_object"})).unwrap().is_null());
        assert!(execute_stored(joiner, br#"{"op":"adopt_recovery"}"#, &recovery_snapshot).is_err());
        call(joiner, recover.clone()).unwrap();
        poll_recovery();
        poll_range(joiner).unwrap();
        assert_eq!(
            call(joiner, json!({"op":"stage_recovery_range"})).unwrap()["state"],
            "recovery_no_new_objects"
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
        call(
            joiner,
            json!({"op":"adopt_reception", "snapshot":live["snapshot"]}),
        )
        .unwrap();
        assert_eq!(take_pending(joiner)["payload"], json!([8]));
        // The live object was already received: recovery finds nothing new.
        let mut continuation = recover;
        continuation["after"] = json!(head);
        continuation["through"] = json!(head + 1);
        call(joiner, continuation).unwrap();
        poll_recovery();
        poll_range(joiner).unwrap();
        assert_eq!(
            call(joiner, json!({"op":"stage_recovery_range"})).unwrap()["state"],
            "recovery_no_new_objects"
        );
        let [_, durable] = execute_stored(joiner, br#"{"op":"seal_workspace"}"#, &[]).unwrap();
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
                .recovery.cutoff
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
            assert!(session.delivery.publisher.as_ref().unwrap().head() > 0);
            assert_eq!(session.delivery.inbox.as_ref().unwrap().pending_count(), 0);
        }
        assert!(call(restored, json!({"op":"poll_pending_object"})).unwrap().is_null());
        call(
            admin,
            json!({"op":"install_member_policy", "revision":20,"topics":["streams/objects"]}),
        )
        .unwrap();
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
        let ack =|handle, pending: &Value| {
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
        // Registering the link is itself a membership step the restored
        // member must accept before the service's Add.
        let staged_link = call(
            admin,
            json!({"op":"stage_invitation","personal":false,"expires_at":0}),
        )
        .unwrap();
        let registration = call(
            admin,
            json!({"op":"adopt_admission","snapshot":staged_link["snapshot"]}),
        )
        .unwrap();
        let invite = registration["issued_invitation"].clone();
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
        let fetch = || {
            call(
                restored,
                json!({"op":"fetch_membership_update", "peer":peer}),
            )
            .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
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
            }
        };
        let fetched = fetch();
        assert_eq!(fetched["state"], "membership_update_available");
        assert_eq!(fetched["step"]["commit"], registration["step"]["commit"]);
        assert!(fetched.get("welcome").is_none());
        drop(admission);
        let pending_count = || {
            session(restored)
                .unwrap()
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .delivery.inbox
                .as_ref()
                .unwrap()
                .pending_count()
        };
        // 32 recovered objects are still pending: neither the registration
        // step nor the Add is delayed, and each candidate carries them (A3).
        assert_eq!(pending_count(), 32);
        let registered = json!({"op":"stage_admission_update", "step":fetched["step"]});
        let [_, saved] =
            execute_stored(restored, &serde_json::to_vec(&registered).unwrap(), &[]).unwrap();
        execute_stored(restored, br#"{"op":"adopt_admission"}"#, &saved).unwrap();
        assert_eq!(pending_count(), 32);
        let fetched = fetch();
        assert_eq!(fetched["state"], "membership_update_available");
        assert_eq!(fetched["step"], step);
        assert!(fetched.get("welcome").is_none());
        let update = json!({"op":"stage_admission_update", "step":fetched["step"]});
        assert_eq!(pending_count(), 32);
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
        for number in 118..150 {
            let pending = call(restored, json!({"op":"poll_pending_object"})).unwrap();
            assert_eq!(pending["payload"], json!([number]));
            ack(restored, &pending);
        }
        println!(
            "NATIVE_OBJECT_INBOX live_pending_restart=true acknowledgement_restart=true missed_recovery=true pending_carried_across_epoch=true adapter_callback=not_exercised"
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
