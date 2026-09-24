//! Session-wide steps that every subsystem uses: the committed workspace,
//! candidate sealing, the delivery state that crosses a membership step, and
//! the lifecycle phase.

use std::sync::Arc;

use arachne_api::{ApiError, ErrorCode};

use crate::errors::{self, delivery, security};
use crate::workspace_activity::ActivityView;
use crate::{Session, WorkspacePhase, membership, persistence};

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
    session
        .committed
        .publish(workspace.clone(), session.node.id());
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
    session.activity.projection()
}

/// The lifecycle phase, typed.
pub(crate) fn activity_view(session: &Session) -> ActivityView {
    session.activity.view()
}

/// The candidate bytes the host saves: a random token with native storage,
/// else the sealed state.
pub(crate) fn seal_state(
    native: bool,
    workspace: &arachne_security::Workspace,
    key: &arachne_security::StorageKey,
    publisher: Option<&arachne_delivery::PublisherLog>,
    inbox: Option<&arachne_delivery::inbox::ObjectInbox>,
) -> Result<Vec<u8>, ApiError> {
    if native {
        return persistence::candidate_token();
    }
    match (inbox, publisher) {
        (Some(inbox), Some(publisher)) => inbox
            .seal(workspace, key, publisher)
            .map_err(delivery(ErrorCode::StorageFailed)),
        (None, None) => workspace
            .seal(key)
            .map_err(security(ErrorCode::StorageFailed)),
        _ => Err(ApiError::internal(
            "object inbox and publisher state go together",
        )),
    }
}

// Pending application objects never block a membership step: they are
// authenticated plaintext and `carry_delivery` keeps them (A3).
pub(crate) fn check_epoch_transition(session: &mut Session) -> Result<(), ApiError> {
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
