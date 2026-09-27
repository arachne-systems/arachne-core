//! Session-wide steps that every subsystem uses: the committed workspace,
//! candidate sealing, the delivery state that crosses a membership step, and
//! the lifecycle phase.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use arachne_api::{ApiError, ErrorCode};
use arachne_node::{Node, Timeouts};
use serde_json::Value;
use tokio::runtime::Handle;

use crate::errors::{self, delivery};
use crate::ops::join::{JoinLifecycle, PendingCheckpointExchange, PendingJoinExchange};
use crate::ops::recovery::{
    PendingCurrentView, PendingDirectRange, PendingRange, ReadyCurrentView, ReadyDirectRange,
    ReadyRange,
};
use crate::workspace_activity::ActivityView;
use crate::{
    MAX_ADMISSION_WAITERS, WorkspaceActivity, WorkspacePhase, admission_waiters, committed_view,
    interest, membership, persistence, presence, resources,
};

pub(crate) enum WorkspaceTransition {
    RoutedPublication(
        arachne_routing::PublicationContext,
        arachne_node::DeliveryClass,
        Vec<u8>,
        Vec<[u8; 32]>,
        Vec<[u8; 32]>,
        bool,
    ),
    /// An automatic re-publication after fork recovery. The workspace
    /// driver saves it and adopts it through its own transition lifecycle.
    Republication(
        arachne_routing::PublicationContext,
        arachne_node::DeliveryClass,
        Vec<u8>,
        Vec<[u8; 32]>,
        Vec<[u8; 32]>,
        bool,
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
    /// A committed management step: the intent, the history authorization
    /// receivers verify (a signed order for revocations) and the commit.
    Management(
        arachne_security::ManagementAction,
        arachne_security::MembershipAuthorization,
        Vec<u8>,
    ),
    WorkspaceName,
    /// This member's own self-update commit (ADR A2 step 5).
    SelfUpdate(Vec<u8>),
    Invitation(
        Box<arachne_security::Invitation>,
        Vec<u8>,
        arachne_security::ManagementAction,
        Vec<u8>,
    ),
    Join,
}

pub(crate) struct StagedWorkspace {
    pub(crate) publisher: Option<arachne_delivery::PublisherLog>,
    pub(crate) inbox: Option<arachne_delivery::inbox::ObjectInbox>,
    pub(crate) transition: WorkspaceTransition,
    pub(crate) workspace: arachne_security::Workspace,
    pub(crate) snapshot: Vec<u8>,
}

pub(crate) struct QueuedAdmission {
    pub(crate) checkpoint: Option<Vec<u8>>,
    pub(crate) display_name: Option<String>,
    pub(crate) approval_automatic: Option<bool>,
    pub(crate) validated: arachne_security::ValidatedAdmission,
}

pub(crate) struct PendingAdmissionApproval {
    pub(crate) attempt: arachne_security::AdmissionAttempt,
    pub(crate) queued: QueuedAdmission,
    pub(crate) delivered: bool,
    pub(crate) acknowledged: bool,
}

pub(crate) struct PendingControl<Q> {
    pub(crate) query: Q,
    pub(crate) peer: [u8; 32],
    pub(crate) task: tokio::task::JoinHandle<Result<Vec<u8>, arachne_node::Error>>,
}
impl<Q> Drop for PendingControl<Q> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The transport services this endpoint was bound with, for `describe`.
#[derive(Clone, Copy)]
pub(crate) struct TransportSummary {
    pub(crate) public_lookup: bool,
    pub(crate) operator_relay: bool,
    pub(crate) timeouts: Timeouts,
}

/// One endpoint session. Each subsystem owns its state in its own struct.
pub(crate) struct Session {
    // Transport and runtime.
    pub(crate) node: Node,
    pub(crate) receiver: arachne_node::MessageReceiver,
    /// The context's shared runtime.
    pub(crate) runtime: Handle,
    pub(crate) overlay_paths: crate::context::OverlayPaths,
    /// Session-owned background tasks, aborted at shutdown.
    pub(crate) tasks: Vec<tokio::task::AbortHandle>,
    // Committed workspace and durable state.
    /// The committed workspace. Shared and never edited in place: a transition
    /// works on a provisional copy, and `commit_workspace` replaces this.
    pub(crate) workspace: Option<Arc<arachne_security::Workspace>>,
    /// The same state, published for inquiries answered without the host.
    pub(crate) committed: committed_view::Published,
    pub(crate) activity: WorkspaceActivity,
    /// Where this session keeps workspace records. Required to hold one.
    pub(crate) storage: Option<persistence::StorageConfig>,
    pub(crate) records: Option<persistence::NativeStore>,
    // Subsystems.
    pub(crate) transition: TransitionState,
    pub(crate) delivery: DeliveryState,
    pub(crate) admission: AdmissionState,
    pub(crate) join: JoinState,
    pub(crate) membership: MembershipState,
    pub(crate) recovery: RecoveryState,
    pub(crate) nearby: NearbyState,
    pub(crate) resources: resources::Jobs,
    pub(crate) presence: presence::Presence,
    pub(crate) interests: interest::Updates,
    /// Set by an op that ended the session (a removal was adopted or
    /// restored). `ops::run` then takes the session and shuts it down.
    pub(crate) ending: bool,
    /// When the op in flight must end (`ops::run` sets it).
    pub(crate) op_deadline: Option<std::time::Instant>,
    /// Ready jobs `next_event` already reported.
    pub(crate) events: crate::events::Reported,
    /// The owning context. Last, so the node closes before a context that
    /// this session keeps alive drops its runtime.
    pub(crate) context: Arc<crate::context::Context>,
}

/// The one staged transition and the one inbound exchange that waits for it.
#[derive(Default)]
pub(crate) struct TransitionState {
    /// A staged workspace candidate that awaits durable adoption.
    pub(crate) staged: Option<StagedWorkspace>,
    /// A staged removal (this member left or was removed) and its token.
    pub(crate) removal: Option<(arachne_security::RemovedMembership, Vec<u8>)>,
    /// A received control request (admission, leave, offer) that waits for
    /// the staged transition before it is answered.
    pub(crate) inbound: Option<arachne_node::ControlRequest>,
}

/// Object delivery state of the committed workspace.
#[derive(Default)]
pub(crate) struct DeliveryState {
    pub(crate) publisher: Option<arachne_delivery::PublisherLog>,
    pub(crate) inbox: Option<arachne_delivery::inbox::ObjectInbox>,
}

/// Owner-side admission intake.
pub(crate) struct AdmissionState {
    pub(crate) queue: arachne_security::AdmissionQueue,
    pub(crate) metadata: BTreeMap<[u8; 32], QueuedAdmission>,
    pub(crate) waiters: admission_waiters::AdmissionWaiters<arachne_node::ControlRequest>,
    pub(crate) pushes: Vec<PendingControl<[u8; 32]>>,
    pub(crate) pending_approvals: BTreeMap<[u8; 32], PendingAdmissionApproval>,
    pub(crate) staged_approval_id: Option<[u8; 32]>,
    // The bounded set of queued membership transitions handed to the durable
    // stage/adopt boundary; retained replies remain independently retryable.
    pub(crate) in_flight: Vec<arachne_security::AdmissionAttempt>,
    // Forced-progress trigger for batch staging: admission packets read since
    // the last staging attempt. Duplicate retries can keep the inbox non-empty
    // for ever; a count of reads ends that without waiting on a clock.
    pub(crate) reads_since_stage: usize,
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
pub(crate) struct JoinState {
    pub(crate) pending: Option<arachne_security::PendingJoin>,
    pub(crate) lifecycle: Option<JoinLifecycle>,
    pub(crate) checkpoint_exchange: Option<PendingCheckpointExchange>,
    pub(crate) exchange: Option<PendingJoinExchange>,
    /// History this session already fetched for the pending join, beyond the
    /// last rollover boundary the host still carries. Untrusted until
    /// `StageJoin` replays it through the verifier from the pinned checkpoint.
    pub(crate) history_prefix: Vec<Value>,
}

/// Membership reconciliation: queries, offers, gossip and profiles.
pub(crate) struct MembershipState {
    pub(crate) fork: membership::fork::ForkState,
    pub(crate) update: Option<PendingControl<membership::StateBasis>>,
    pub(crate) offer: Option<PendingControl<u64>>,
    pub(crate) offer_requires_adoption: bool,
    /// Last failed membership query per peer, for the peer-choice cooldown.
    pub(crate) peer_failures: BTreeMap<[u8; 32], std::time::Instant>,
    /// The staged candidate came from a peer's step, not a local commit.
    pub(crate) staged_step_received: bool,
    /// Gossiped steps that skip ahead of this node's epoch, keyed by the
    /// epoch they extend. Bounded; applied in order as earlier steps land.
    pub(crate) steps_ahead: BTreeMap<u64, Vec<u8>>,
    /// The newest epoch heard by gossip or presence, and members that have it.
    /// A hint only: the steps are pulled and verified.
    pub(crate) head: Option<(u64, Vec<[u8; 32]>)>,
    /// One range pull toward `head`, keyed by the epoch it extends.
    pub(crate) range_pull: Option<PendingControl<u64>>,
    /// Membership gossip outcomes, for workspace_metrics.
    pub(crate) gossip_counts: Arc<membership::GossipCounts>,
    /// One page pull of a peer's retained names, and the peer sets already
    /// walked to the end (peer -> its profile digest), bounded.
    pub(crate) profile_pull: Option<PendingControl<membership::ProfilePull>>,
    pub(crate) profiles_walked: BTreeMap<[u8; 32], [u8; 32]>,
    /// Gossiped profiles of members not yet in this roster (bounded).
    pub(crate) profiles_pending: VecDeque<Vec<u8>>,
    /// Retained member profiles, shared with the inquiry responder.
    pub(crate) profiles: membership::Profiles,
    pub(crate) peer_profile_summaries: BTreeMap<[u8; 32], [u8; 32]>,
    /// When this member self-updates next (B3c).
    pub(crate) self_update: membership::self_update::SelfUpdatePolicy,
}

impl MembershipState {
    pub(crate) fn new(profiles: membership::Profiles) -> Self {
        Self {
            fork: membership::fork::ForkState::default(),
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
            self_update: membership::self_update::SelfUpdatePolicy::new(std::time::Instant::now()),
        }
    }
}

/// Recovery, direct recovery and current-view repair jobs.
#[derive(Default)]
pub(crate) struct RecoveryState {
    pub(crate) cutoff: Option<PendingControl<arachne_delivery::wire::CutoffQuery>>,
    pub(crate) current_view: Option<PendingCurrentView>,
    pub(crate) ready_current_view: Option<ReadyCurrentView>,
    pub(crate) range: Option<PendingRange>,
    pub(crate) ready_range: Option<ReadyRange>,
    pub(crate) direct_range: Option<PendingDirectRange>,
    pub(crate) ready_direct_range: Option<ReadyDirectRange>,
    pub(crate) direct_miss: Option<arachne_delivery::wire::DirectRangeQuery>,
}

/// Device-level nearby advertisement.
#[derive(Default)]
pub(crate) struct NearbyState {
    pub(crate) workspaces: BTreeMap<[u8; 32], Vec<u8>>,
    pub(crate) identity: Option<String>,
}

impl Session {
    /// The one constructor: an empty session around a bound node.
    pub(crate) fn new(
        node: Node,
        receiver: arachne_node::MessageReceiver,
        context: Arc<crate::context::Context>,
        committed: committed_view::Published,
        presence: presence::Presence,
    ) -> Self {
        let profiles = committed.profiles();
        Self {
            node,
            receiver,
            runtime: context.handle().clone(),
            overlay_paths: context.overlay_paths(),
            tasks: Vec::new(),
            workspace: None,
            committed,
            activity: WorkspaceActivity::default(),
            storage: None,
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
            op_deadline: None,
            events: Default::default(),
            context,
        }
    }
}

/// The one place a workspace becomes the committed one. Callers have already
/// saved and adopted it; publishing here is what lets inquiries see it.
pub(crate) fn commit_workspace(session: &mut Session, workspace: arachne_security::Workspace) {
    // Object delivery is the only receive path: an active member always has
    // an inbox and a publisher log.
    if workspace.member().is_some() {
        if session.delivery.inbox.is_none() {
            session.delivery.inbox = Some(arachne_delivery::inbox::ObjectInbox::new(
                workspace.id(),
                workspace.epoch(),
            ));
        }
        if session.delivery.publisher.is_none() {
            session.delivery.publisher = arachne_delivery::PublisherLog::new(&workspace).ok();
        }
    }
    let workspace = Arc::new(workspace);
    session.committed.publish(
        workspace.clone(),
        session.node.id(),
        membership::fork::shared_orders(session),
    );
    session.workspace = Some(workspace);
    // Any committed workspace change, including a name-only update, must be
    // advertised on the next native presence drain.  Otherwise peers keep
    // querying the old head until the periodic refresh interval elapses.
    session.presence.announce_next();
    // Names held for members this step admits.
    membership::retain_held_profiles(session);
}

pub(crate) fn transition_activity(
    session: &mut Session,
    phase: WorkspacePhase,
    reason: Option<&str>,
) -> Result<(), ApiError> {
    session.activity.transition(phase, reason)
}

/// The lifecycle phase as JSON, for replies that are still JSON values.
pub(crate) fn activity_value(session: &Session) -> serde_json::Value {
    serde_json::to_value(activity_view(session)).unwrap_or(serde_json::Value::Null)
}

/// The lifecycle phase, with branch recovery projected for an active owner.
/// Terminal and explicit lifecycle operations retain their own reasons.
pub(crate) fn activity_view(session: &Session) -> ActivityView {
    let mut view = session.activity.view();
    if matches!(
        view.phase,
        WorkspacePhase::Active | WorkspacePhase::Recovering
    ) && let Some(reason) = membership::fork::recovery_reason(session)
    {
        view.phase = WorkspacePhase::Recovering;
        view.reason = Some(reason.to_owned());
    }
    view
}

/// The opaque token of a new candidate. Staging needs record storage: the
/// adopt step saves the candidate there before it becomes live.
pub(crate) fn seal_state(native: bool) -> Result<Vec<u8>, ApiError> {
    if !native {
        return Err(persistence::storage_required());
    }
    persistence::candidate_token()
}

// Pending application objects never block a membership step: they are
// authenticated plaintext and `carry_delivery` keeps them (A3).
pub(crate) fn check_epoch_transition(session: &mut Session) -> Result<(), ApiError> {
    membership::fork::require_active_branch(session)?;
    session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    // Background discovery/download has accepted no application work. A new
    // epoch invalidates its query anyway; cancel it instead of making normal
    // membership actions race the periodic history poller. Accepted inbox and
    // recovered deliveries above must still drain before this point.
    drop(session.recovery.cutoff.take());
    drop(session.recovery.range.take());
    session.recovery.ready_range = None;
    drop(session.recovery.direct_range.take());
    session.recovery.ready_direct_range = None;
    session.recovery.direct_miss = None;
    drop(session.recovery.current_view.take());
    session.recovery.ready_current_view = None;
    Ok(())
}

/// Delivery state for a membership candidate `next` (A3). Pending objects,
/// replay state of the receive window and per-epoch publisher logs survive
/// the step; save them with the candidate.
pub(crate) fn carry_delivery(
    session: &Session,
    next: &arachne_security::Workspace,
) -> Result<
    (
        Option<arachne_delivery::PublisherLog>,
        Option<arachne_delivery::inbox::ObjectInbox>,
    ),
    ApiError,
> {
    let previous = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    if next.member().is_none() {
        return Ok((None, None));
    }
    let inbox = match &session.delivery.inbox {
        Some(inbox) => inbox.advance(previous, next),
        None => Ok(arachne_delivery::inbox::ObjectInbox::new(
            next.id(),
            next.epoch(),
        )),
    }
    .map_err(delivery(ErrorCode::Internal))?;
    let publisher = match &session.delivery.publisher {
        Some(publisher) => publisher.advance(previous, next),
        None => arachne_delivery::PublisherLog::new(next),
    }
    .map_err(delivery(ErrorCode::Internal))?;
    Ok((Some(publisher), Some(inbox)))
}
