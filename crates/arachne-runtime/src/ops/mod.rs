//! Typed session operations (ADR A1/A4, step 2).
//!
//! Each op is one function `fn op(session: &mut Session, args) ->
//! Result<Reply, ApiError>` in the module of its subsystem. The typed
//! [`crate::Client`] and the deprecated JSON dispatcher ([`crate::json`]) both
//! call these functions through [`run`], which applies the rules that hold
//! around every op: the session lock, the pending-candidate guards
//! ([`admit`]), and the wake-ups and shutdown after the op.

use arachne_api::ApiError;

use crate::errors;
use crate::Session;

pub(crate) mod admission;
pub(crate) mod candidate;
pub(crate) mod debug;
pub(crate) mod invitation;
pub(crate) mod join;
pub(crate) mod management;
pub(crate) mod membership;
pub(crate) mod nearby;
pub(crate) mod policy;
pub(crate) mod publication;
pub(crate) mod receive;
pub(crate) mod recovery;
pub(crate) mod workspace;

/// Every op, without its arguments. The guards key on this.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Op {
    Resource,
    WorkspaceMetrics,
    MoqMetrics,
    EnableMoqDelivery,
    WorkspaceState,
    ResetWorkspace,
    DiscardWorkspaceCandidate,
    NetworkChange,
    NearbyEndpoints,
    SetNearbyIdentity,
    NearbyWorkspaces,
    SetNearbyWorkspace,
    SendNearbyInvitation,
    PollWorkspacePresence,
    FetchMembershipUpdate,
    PollMembershipUpdate,
    NextMembershipPeer,
    OfferMembershipUpdate,
    OfferStagedMembershipUpdate,
    PollMembershipOffer,
    FetchRecoveryRange,
    PollRecoveryRange,
    NextDirectGap,
    FetchDirectRecovery,
    PollDirectRecovery,
    StageDirectRecovery,
    StageDirectMiss,
    CancelDirectRecovery,
    StageRecoveryRange,
    AdoptRecovery,
    CancelRecoveryRange,
    PollRecoveryCutoff,
    DiscoverRecoveryCutoff,
    FetchCurrentView,
    PollCurrentView,
    StageCurrentView,
    AdoptCurrentView,
    CancelCurrentView,
    FetchInvitationCheckpoint,
    RequestAdmission,
    StageNetworkPublication,
    PollPendingObject,
    StageObjectAcknowledgement,
    StageObjectRejection,
    PollProtected,
    EndpointInfo,
    ControlExchange,
    AdoptPublication,
    AdoptReception,
    PollAdmission,
    DriveWorkspace,
    ListAdmissionApprovals,
    AcknowledgeAdmissionApproval,
    SendAdmissionReply,
    StageJoin,
    AdoptJoin,
    StageAdmission,
    MemberRoster,
    UseServiceProfile,
    LeaveViaPeer,
    StageSoloLeave,
    StageManagement,
    StageInvitation,
    StageInvitationApproval,
    StageInvitationDecline,
    InvitationControls,
    StageWorkspaceName,
    StageWorkspaceNameUpdate,
    StageWorkspaceNameCheckpoint,
    InspectInvitation,
    StageAdmissionUpdate,
    AdoptAdmission,
    RetainedAdmission,
    BeginJoin,
    DriveJoin,
    SealPendingJoin,
    RestorePendingJoin,
    CreateWorkspace,
    SealWorkspace,
    RestoreWorkspace,
    AddAddressHint,
    InstallWorkspacePolicy,
    InstallMemberPolicy,
    InstallVerifiedPolicy,
    SetInterest,
    PollInterest,
    Subscribe,
    Unsubscribe,
    Publish,
    Poll,
}

impl Op {
    /// Ops that run whatever candidate or exchange is pending.
    fn always_allowed(self) -> bool {
        matches!(
            self,
            Op::ResetWorkspace
                | Op::DiscardWorkspaceCandidate
                | Op::DriveWorkspace
                | Op::DriveJoin
                | Op::WorkspaceState
                | Op::WorkspaceMetrics
                | Op::MoqMetrics
                | Op::NetworkChange
                | Op::NearbyEndpoints
                | Op::NearbyWorkspaces
                | Op::SetNearbyWorkspace
                | Op::SetNearbyIdentity
                | Op::SendNearbyInvitation
        )
    }

    /// Ops allowed while a workspace candidate awaits durable adoption.
    fn allowed_while_staged(self) -> bool {
        matches!(
            self,
            Op::AdoptAdmission
                | Op::AdoptJoin
                | Op::AdoptPublication
                | Op::AdoptReception
                | Op::AdoptRecovery
                | Op::AdoptCurrentView
                | Op::PollAdmission
                | Op::OfferStagedMembershipUpdate
                | Op::PollMembershipOffer
                | Op::DiscardWorkspaceCandidate
        )
    }

    /// Ops allowed while a received exchange awaits adoption or its reply.
    fn allowed_while_inbound(self) -> bool {
        matches!(
            self,
            Op::AdoptAdmission | Op::AdoptJoin | Op::SendAdmissionReply | Op::PollAdmission
        )
    }
}

/// The guards that hold before an op runs, in their fixed order.
pub(crate) fn admit(session: &Session, op: Op) -> Result<(), ApiError> {
    if op.always_allowed() {
        return Ok(());
    }
    if session.transition.removal.is_some() && op != Op::AdoptAdmission {
        return Err(ApiError::wrong_state(
            "removed membership awaits durable adoption",
        ));
    }
    if session.transition.removal.is_some() {
        return Ok(());
    }
    if session.transition.staged.is_some() && !op.allowed_while_staged() {
        return Err(ApiError::wrong_state(
            "workspace candidate awaits durable adoption; close and restore saved state to recover",
        ));
    }
    if session.transition.inbound.is_some() && !op.allowed_while_inbound() {
        return Err(ApiError::wrong_state(
            "received admission awaits adoption or reply; close to recover",
        ));
    }
    if session.workspace.is_some() {
        match op {
            Op::Publish => {
                return Err(ApiError::wrong_state(
                    "unprotected publication is disabled for an admitted workspace",
                ));
            }
            Op::InstallVerifiedPolicy => {
                return Err(ApiError::wrong_state(
                    "admitted workspace routing must derive from verified membership",
                ));
            }
            Op::Poll => {
                return Err(ApiError::wrong_state(
                    "use poll_protected for an admitted workspace",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Run `op` inside an op that already holds the session (the drive ops):
/// the inner op passes the same guards as a call of its own.
pub(crate) fn nested<T>(
    session: &mut Session,
    op: Op,
    body: impl FnOnce(&mut Session) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    admit(session, op)?;
    body(session)
}

/// A session is busy while a candidate or a received exchange is pending.
pub(crate) fn admission_busy(session: &Session) -> bool {
    session.transition.staged.is_some() || session.transition.inbound.is_some()
}

/// Clear the control cancel latch without a change notice when it is
/// already clear: every notice, even to `false`, stops the control
/// exchanges in flight (presence, recovery and interest tasks).
pub(crate) fn clear_cancel(latch: &tokio::sync::watch::Sender<bool>) {
    latch.send_if_modified(|cancelled| std::mem::replace(cancelled, false));
}

/// Run one op on a live session: lock, guard, run, then the wake-ups and a
/// shutdown if the op ended the session. The typed `Client` and the JSON
/// dispatcher both come through here.
pub(crate) fn run<T>(
    handle: i64,
    op: Op,
    body: impl FnOnce(&mut Session) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let entry = crate::registry::entry(handle)?;
    // The deadline counts from the call, so a wait for the lock counts too.
    let Some(limit) = entry.deadline() else {
        return run_locked(handle, &entry.shared, op, None, body);
    };
    let deadline = std::time::Instant::now() + limit;
    let result = run_locked(handle, &entry.shared, op, Some(deadline), body);
    match result {
        Err(_) if crate::deadline::expired(Some(deadline)) => Err(ApiError::DeadlineExceeded),
        result => result,
    }
}

fn run_locked<T>(
    handle: i64,
    shared: &crate::registry::SharedSession,
    op: Op,
    deadline: Option<std::time::Instant>,
    body: impl FnOnce(&mut Session) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let mut guard = shared
        .lock()
        .map_err(errors::poisoned("node session unavailable"))?;
    let session = guard.as_mut().ok_or_else(errors::closed)?;
    let busy_before = admission_busy(session);
    session.op_deadline = deadline;
    let result = if crate::deadline::expired(deadline) {
        Err(ApiError::DeadlineExceeded)
    } else {
        admit(session, op).and_then(|()| body(session))
    };
    session.op_deadline = None;
    // Explicit cancel stops node control exchanges. Close
    // removes the handle first; its cancel stays set, so an op queued on
    // this lock cannot delay the close.
    session.events.rearm_queues();
    let closing = crate::registry::entry(handle).map_or(true, |entry| entry.signal.is_closed());
    if !closing {
        clear_cancel(&session.node.control_cancellation());
    }
    // Control requests set aside while a commit was pending raised their
    // signal on arrival, and the host already found nothing it could serve.
    // Wake it again now that they can be served.
    if session.transition.staged.is_none() {
        session.membership.staged_step_received = false;
    }
    if session.transition.staged.is_none()
        && session.transition.inbound.is_none()
        && !session.admission.queue.is_empty()
    {
        // Intake replies leave the request held while the host commits the
        // next admission. Wake the host for that second, local staging pass.
        session.node.rearm_control_signal();
    }
    if busy_before && !admission_busy(session) && session.node.has_deferred_controls() {
        session.node.rearm_control_signal();
    }
    // A gossiped step held for a later epoch spent its arrival signal. Once
    // the epoch before it lands, wake the host to stage it.
    if !admission_busy(session)
        && session.workspace.as_ref().is_some_and(|owner| {
            session
                .membership
                .steps_ahead
                .contains_key(&owner.epoch())
        })
    {
        session.node.rearm_control_signal();
    }
    // A removal ended the session: take it out, release the lock before the
    // blocking shutdown, so other callers fail fast with "node is closed".
    let ended = if session.ending { guard.take() } else { None };
    drop(guard);
    if let Some(ended) = ended {
        crate::shutdown_session(ended)?;
    }
    result
}
