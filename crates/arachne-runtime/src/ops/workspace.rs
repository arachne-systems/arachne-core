//! The workspace itself: create and restore (from record storage), reset,
//! discard a candidate, and its state and metrics.

use std::sync::Arc;

use arachne_api::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::client::{
    ConnectionCapacityMetrics, ControlTimingMetrics, DurationSummary, MembershipGossipMetrics,
};
use crate::errors::{self, delivery, security};
use crate::ops::candidate::MemberView;
use crate::session::{activity_view, commit_workspace, transition_activity};
use crate::workspace_activity::ActivityView;
use crate::{
    MembershipState, Session, WorkspaceActivity, WorkspacePhase, persistence, presence,
    resources,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateArgs {
    pub display_name: String,
    pub workspace_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreArgs {
    pub workspace: [u8; 32],
    /// The anchor the host saved from `record_freshness` (40 bytes).
    #[serde(default)]
    pub freshness: Option<Vec<u8>>,
}

/// A workspace this session now owns (created or restored).
#[derive(Clone, Debug, Serialize)]
pub(crate) struct WorkspaceOpened {
    pub workspace: [u8; 32],
    pub workspace_name: Option<String>,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_name_missing_history: Option<u64>,
    pub members: usize,
    pub member: Option<MemberView>,
    pub durable: bool,
    pub activity: ActivityView,
}

impl WorkspaceOpened {
    /// `activity` is filled by the caller after the phase changes.
    pub(crate) fn of(
        owner: &arachne_security::Workspace,
        missing_history: Option<u64>,
        durable: bool,
    ) -> Result<Self, ApiError> {
        Ok(Self {
            workspace: owner.id(),
            workspace_name: owner
                .workspace_name()
                .map_err(security(ErrorCode::Internal))?,
            epoch: owner.epoch(),
            workspace_name_missing_history: missing_history,
            members: owner.member_count(),
            member: owner.member().map(|member| MemberView {
                id: member.id(),
                display_name: member.display_name().to_owned(),
            }),
            durable,
            activity: ActivityView {
                phase: WorkspacePhase::Empty,
                reason: None,
            },
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ResetReply {
    pub state: &'static str,
    pub changed: bool,
    pub durable: bool,
    pub reset_activity: ActivityView,
    pub activity: ActivityView,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct Discarded {
    pub state: &'static str,
    pub discarded: bool,
    pub offer_cancelled: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct StateView {
    pub activity: ActivityView,
    pub workspace_ready: bool,
    pub durable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PathView {
    pub member: [u8; 32],
    pub route: &'static str,
    pub rtt_ms: u64,
}

/// Local counters for adapters and diagnostics.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct MetricsReply {
    pub workspace: [u8; 32],
    pub session: [u8; 32],
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub receive_queue: usize,
    pub admission_queue: usize,
    pub admission_queue_bytes: usize,
    pub admission_waiters: usize,
    pub control_timing: ControlTimingMetrics,
    pub membership_gossip: MembershipGossipMetrics,
    pub connection_capacity: ConnectionCapacityMetrics,
    pub gossip_neighbors: usize,
    pub admission_in_flight: usize,
    pub approval_pending: usize,
    pub activity: ActivityView,
    pub pending_objects: usize,
    pub repair_jobs: usize,
    pub paths: Vec<PathView>,
    pub paths_limited: bool,
}

fn already_owned() -> ApiError {
    ApiError::wrong_state("session already owns a workspace")
}

pub(crate) fn create(session: &mut Session, args: CreateArgs) -> Result<WorkspaceOpened, ApiError> {
    if session.workspace.is_some() || session.join.pending.is_some() {
        return Err(already_owned());
    }
    transition_activity(session, WorkspacePhase::Creating, None)?;
    let workspace = arachne_security::Workspace::create_named(
        &session.node,
        &args.display_name,
        args.workspace_name.as_deref(),
    )
    .map_err(|error| {
        let _ = transition_activity(session, WorkspacePhase::Failed, Some("create_failed"));
        security(ErrorCode::InvalidInput)(error)
    })?;
    // Saved before it becomes the committed workspace.
    let publisher = arachne_delivery::PublisherLog::new(&workspace)
        .map_err(delivery(ErrorCode::Internal))?;
    let inbox = arachne_delivery::inbox::ObjectInbox::new(workspace.id(), workspace.epoch());
    if let Err(error) =
        persistence::commit_created(session, &workspace, Some(&publisher), Some(&inbox))
    {
        let _ = transition_activity(session, WorkspacePhase::Failed, Some("create_failed"));
        return Err(error);
    }
    transition_activity(session, WorkspacePhase::Active, None)?;
    let mut value = WorkspaceOpened::of(&workspace, None, true)?;
    session.delivery.publisher = Some(publisher);
    session.delivery.inbox = Some(inbox);
    commit_workspace(session, workspace);
    value.activity = activity_view(session);
    Ok(value)
}

/// Restore the stored workspace, pending join or removal. A stored
/// removal ends the session.
pub(crate) fn restore(
    session: &mut Session,
    args: RestoreArgs,
) -> Result<persistence::Restored, ApiError> {
    let expected = args
        .freshness
        .map(|bytes| {
            arachne_store::FreshnessAnchor::from_bytes(&bytes)
                .map_err(|_| ApiError::invalid_input("freshness", "invalid freshness anchor"))
        })
        .transpose()?;
    persistence::restore(session, args.workspace, expected)
}

/// Forget all workspace state; with native storage, first write the reset
/// marker so a crash cannot bring the old state back.
pub(crate) fn reset(session: &mut Session) -> Result<ResetReply, ApiError> {
    let changed = session.workspace.is_some()
        || session.join.pending.is_some()
        || session.records.is_some()
        || session.activity.phase != WorkspacePhase::Empty;
    let mut resetting = session.activity.clone();
    resetting.transition(WorkspacePhase::Resetting, Some("reset_requested"))?;
    let reset_presence = presence::Presence::new()?;
    let durable = session.records.is_some();
    if durable {
        persistence::reset_records(session, &resetting)?;
    }

    session.overlay_paths.release_all();
    session.presence = reset_presence;
    session.resources = resources::Jobs::default();
    session.interests.cancel();
    // The shared profile set stays: the committed view clears it below.
    session.membership = MembershipState::new(Arc::clone(&session.membership.profiles));
    session.recovery = Default::default();
    session.delivery = Default::default();
    session.transition = Default::default();
    session.admission = Default::default();
    session.join = Default::default();
    // The device's nearby identity is not workspace state.
    session.nearby.workspaces.clear();
    session.workspace = None;
    session.committed.clear();
    session.records = None;
    session.activity = WorkspaceActivity::default();

    Ok(ResetReply {
        state: "reset",
        changed,
        durable,
        reset_activity: resetting.view(),
        activity: activity_view(session),
    })
}

/// Drop the staged candidate (and a pending staged offer).
pub(crate) fn discard_candidate(session: &mut Session) -> Result<Discarded, ApiError> {
    if session.transition.removal.is_some() {
        return Err(ApiError::wrong_state(
            "removed membership awaits durable adoption",
        ));
    }
    if session.transition.inbound.is_some() {
        return Err(ApiError::wrong_state(
            "received admission awaits adoption or reply",
        ));
    }
    if let Some(staged) = &session.transition.staged
        && persistence::candidate_saved(session, &staged.snapshot)
    {
        // Storage already holds it: live state would fork from storage.
        return Err(ApiError::wrong_state(
            "candidate is already in storage; adopt it, or close and restore",
        ));
    }
    let discarded = session.transition.staged.take().is_some();
    if discarded {
        // The batch goes back to intake: a retried request is assessed again
        // instead of waiting for an adoption that will never come. A pending
        // approval stays pending.
        session.admission.in_flight.clear();
        session.admission.staged_approval_id = None;
    }
    let offer_cancelled = session.membership.offer.take().is_some();
    session.membership.offer_requires_adoption = false;
    session.membership.staged_step_received = false;
    Ok(Discarded {
        state: "workspace_candidate_discarded",
        discarded,
        offer_cancelled,
    })
}

pub(crate) fn state(session: &mut Session) -> Result<StateView, ApiError> {
    Ok(StateView {
        activity: activity_view(session),
        workspace_ready: session.workspace.is_some(),
        durable: session.records.is_some(),
        workspace: session
            .workspace
            .as_ref()
            .map(|owner| owner.id())
            .or_else(|| session.join.pending.as_ref().map(|pending| pending.workspace_id())),
    })
}

fn duration(timing: arachne_node::Timing) -> DurationSummary {
    DurationSummary {
        count: timing.count,
        total_us: timing.total_us,
        max_us: timing.max_us,
    }
}

pub(crate) fn metrics(session: &mut Session) -> Result<MetricsReply, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let roster = owner
        .member_roster()
        .map_err(security(ErrorCode::Internal))?;
    let metrics = session.node.transport_metrics();
    let paths = metrics
        .paths
        .iter()
        .filter_map(|path| {
            let member = roster
                .iter()
                .find(|member| member.endpoint == path.endpoint)?;
            Some(PathView {
                member: member.id,
                route: path.route,
                rtt_ms: path.rtt_ms,
            })
        })
        .collect();
    let timing = session.node.control_timing();
    let capacity = session.node.connection_capacity();
    let recovery = &session.recovery;
    Ok(MetricsReply {
        workspace: owner.id(),
        session: session.node.id(),
        received_bytes: metrics.received_bytes,
        sent_bytes: metrics.sent_bytes,
        receive_queue: metrics.receive_queue,
        admission_queue: session.admission.queue.len(),
        admission_queue_bytes: session.admission.queue.bytes(),
        admission_waiters: session.admission.waiters.len(),
        control_timing: ControlTimingMetrics {
            inquiry: duration(timing.inquiry),
            host_wait: duration(timing.host_wait),
            host_service: duration(timing.host_service),
        },
        membership_gossip: session.membership.gossip_counts.metrics(),
        connection_capacity: ConnectionCapacityMetrics {
            evicted: capacity.evicted,
            refused: capacity.refused,
        },
        gossip_neighbors: session
            .runtime
            .block_on(session.node.live_neighbors(owner.id()))
            .len(),
        admission_in_flight: session.admission.in_flight.len(),
        approval_pending: session.admission.pending_approvals.len(),
        activity: activity_view(session),
        pending_objects: session
            .delivery
            .inbox
            .as_ref()
            .map(|inbox| inbox.pending_count())
            .unwrap_or(0),
        repair_jobs: usize::from(recovery.cutoff.is_some())
            + usize::from(recovery.range.is_some() || recovery.ready_range.is_some())
            + usize::from(recovery.direct_range.is_some() || recovery.ready_direct_range.is_some())
            + usize::from(recovery.current_view.is_some() || recovery.ready_current_view.is_some()),
        paths,
        paths_limited: metrics.paths_limited,
    })
}
