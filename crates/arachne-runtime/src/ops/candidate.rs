//! The adopt step of the stage → save → adopt lifecycle, shared by every
//! group: admission and management, join, publication, reception, recovery
//! and current view. Each adopt op accepts only its own kind of candidate.

use std::time::Duration;

use arachne_api::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::client::DeliveryReport;
use crate::errors::{self, security};
use crate::ops::admission::{admission_reply_page, queue_admission_push, send_inbound_admission_reply};
use crate::session::{activity_view, commit_workspace, transition_activity};
use crate::workspace_activity::ActivityView;
use crate::{Session, WorkspacePhase, WorkspaceTransition, invitation_envelope, membership, report};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdoptArgs {
    /// The exact candidate bytes (token or sealed state) the host saved.
    #[serde(default)]
    pub snapshot: Vec<u8>,
}

/// Which adopt op runs. Each accepts only its own transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdoptKind {
    Admission,
    Join,
    Publication,
    Reception,
    Recovery,
    CurrentView,
}

impl AdoptKind {
    fn accepts(self, transition: &WorkspaceTransition) -> bool {
        matches!(
            (self, transition),
            (
                AdoptKind::Admission,
                WorkspaceTransition::Admission
                    | WorkspaceTransition::Management(_, _)
                    | WorkspaceTransition::WorkspaceName
                    | WorkspaceTransition::Invitation(..)
            ) | (AdoptKind::Join, WorkspaceTransition::Join)
                | (
                    AdoptKind::Recovery,
                    WorkspaceTransition::InboxRecovery { .. } | WorkspaceTransition::DirectMiss { .. }
                )
                | (
                    AdoptKind::CurrentView,
                    WorkspaceTransition::CurrentView { .. }
                )
                | (
                    AdoptKind::Publication,
                    WorkspaceTransition::RoutedPublication(..)
                )
                | (
                    AdoptKind::Reception,
                    WorkspaceTransition::Inbox | WorkspaceTransition::InboxRejected
                )
        )
    }
}

/// A member as a reply shows it.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct MemberView {
    pub id: [u8; 32],
    pub display_name: String,
}

/// The network outcome of an adopted publication.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct PublicationOutcome {
    pub id: [u8; 16],
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission: Option<DeliveryReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct CurrentViewCounts {
    pub cut: u64,
    pub pending: usize,
    pub stale: usize,
}

/// An adopted candidate: the new committed state and what the step did.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Adopted {
    pub workspace: [u8; 32],
    pub workspace_name: Option<String>,
    pub epoch: u64,
    pub workspace_name_missing_history: u64,
    pub members: usize,
    pub durable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_count: Option<u64>,
    #[serde(flatten)]
    pub current_view: Option<CurrentViewCounts>,
    #[serde(flatten)]
    pub publication: Option<PublicationOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_invitation: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results_delivered: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results_pushed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_queued: Option<bool>,
    pub activity: ActivityView,
}

/// This member was removed (or left). The session ends after the reply.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Removed {
    pub workspace: [u8; 32],
    pub epoch: u64,
    pub state: &'static str,
    pub workspace_ready: bool,
    pub member: MemberView,
    pub commit_digest: [u8; 32],
}

impl Removed {
    pub(crate) fn of(removed: &arachne_security::RemovedMembership) -> Self {
        Self {
            workspace: removed.workspace_id(),
            epoch: removed.epoch(),
            state: "removed",
            workspace_ready: false,
            member: MemberView {
                id: removed.member().id(),
                display_name: removed.member().display_name().to_owned(),
            },
            commit_digest: removed.commit_digest(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum AdoptReply {
    Adopted(Box<Adopted>),
    Removed(Removed),
}

impl AdoptReply {
    /// The adopted state; a removal gives `WrongState`.
    pub(crate) fn adopted(self) -> Result<Adopted, ApiError> {
        match self {
            AdoptReply::Adopted(adopted) => Ok(*adopted),
            AdoptReply::Removed(_) => Err(ApiError::wrong_state("this member was removed")),
        }
    }
}

pub(crate) fn adopt_admission(session: &mut Session, args: AdoptArgs) -> Result<AdoptReply, ApiError> {
    adopt(session, AdoptKind::Admission, args.snapshot)
}

pub(crate) fn adopt_join(session: &mut Session, args: AdoptArgs) -> Result<AdoptReply, ApiError> {
    adopt(session, AdoptKind::Join, args.snapshot)
}

pub(crate) fn adopt_publication(
    session: &mut Session,
    args: AdoptArgs,
) -> Result<AdoptReply, ApiError> {
    adopt(session, AdoptKind::Publication, args.snapshot)
}

pub(crate) fn adopt_reception(session: &mut Session, args: AdoptArgs) -> Result<AdoptReply, ApiError> {
    adopt(session, AdoptKind::Reception, args.snapshot)
}

pub(crate) fn adopt_recovery(session: &mut Session, args: AdoptArgs) -> Result<AdoptReply, ApiError> {
    adopt(session, AdoptKind::Recovery, args.snapshot)
}

pub(crate) fn adopt_current_view(
    session: &mut Session,
    args: AdoptArgs,
) -> Result<AdoptReply, ApiError> {
    adopt(session, AdoptKind::CurrentView, args.snapshot)
}

fn require_committed(session: &Session, snapshot: &[u8]) -> Result<(), ApiError> {
    if let Some(store) = &session.records {
        store.require_committed(snapshot).map_err(errors::legacy)?;
    }
    Ok(())
}

/// Adopt the saved candidate of `kind`: the one place a staged candidate or
/// a staged removal becomes committed.
pub(crate) fn adopt(
    session: &mut Session,
    kind: AdoptKind,
    snapshot: Vec<u8>,
) -> Result<AdoptReply, ApiError> {
    if let Some((removed, expected)) = &session.transition.removal {
        // The guards let only adopt_admission through while a removal waits.
        if kind != AdoptKind::Admission {
            return Err(ApiError::wrong_state(
                "removed membership awaits durable adoption",
            ));
        }
        if &snapshot != expected {
            return Err(ApiError::candidate_stale(
                "removed snapshot does not match candidate",
            ));
        }
        require_committed(session, &snapshot)?;
        let value = Removed::of(removed);
        session.ending = true;
        return Ok(AdoptReply::Removed(value));
    }
    let staged = session
        .transition
        .staged
        .as_ref()
        .ok_or_else(|| ApiError::wrong_state("session has no workspace candidate"))?;
    if !kind.accepts(&staged.transition) {
        return Err(ApiError::wrong_state("wrong adoption lifecycle phase"));
    }
    if snapshot != staged.snapshot {
        return Err(ApiError::candidate_stale(
            "workspace snapshot does not match candidate",
        ));
    }
    require_committed(session, &snapshot)?;
    let staged = session.transition.staged.take().unwrap();
    let joined = matches!(&staged.transition, WorkspaceTransition::Join);
    let mut value = Adopted {
        workspace: staged.workspace.id(),
        workspace_name: staged
            .workspace
            .workspace_name()
            .map_err(security(ErrorCode::Internal))?,
        epoch: staged.workspace.epoch(),
        workspace_name_missing_history: staged
            .workspace
            .workspace_name_missing_history()
            .map_err(security(ErrorCode::Internal))?,
        members: staged.workspace.member_count(),
        durable: session.records.is_some(),
        state: None,
        publication_count: None,
        missing_count: None,
        current_view: None,
        publication: None,
        step: None,
        issued_invitation: None,
        results_delivered: None,
        results_pushed: None,
        reply_queued: None,
        activity: activity_view(session),
    };
    session.delivery.publisher = staged.publisher;
    session.delivery.inbox = staged.inbox;
    if matches!(&staged.transition, WorkspaceTransition::Join) {
        transition_activity(session, WorkspacePhase::Synchronizing, None)?;
    }
    commit_workspace(session, staged.workspace);
    let staged_approval_id = session.admission.staged_approval_id;
    // A step this node committed goes out by gossip. A step it
    // received from a peer is already travelling; gossip relays it.
    let received = std::mem::take(&mut session.membership.staged_step_received);
    let committed_here = matches!(staged.transition, WorkspaceTransition::Admission) && !received;
    match staged.transition {
        WorkspaceTransition::Inbox => value.state = Some("inbox_adopted"),
        WorkspaceTransition::InboxRejected => value.state = Some("inbox_rejection_adopted"),
        WorkspaceTransition::InboxRecovery { count } => {
            value.state = Some("recovery_adopted");
            value.publication_count = Some(count);
        }
        WorkspaceTransition::DirectMiss { missing } => {
            value.state = Some("direct_miss_adopted");
            value.missing_count = Some(missing);
        }
        WorkspaceTransition::CurrentView {
            cut,
            pending,
            stale,
        } => {
            value.state = Some("current_view_adopted");
            value.current_view = Some(CurrentViewCounts {
                cut,
                pending,
                stale,
            });
        }
        WorkspaceTransition::RoutedPublication(context, delivery, packet, endpoints, recipients) => {
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
            let mut outcome = PublicationOutcome {
                id: context.id,
                sequence: context.sequence.map(|n| n.get()),
                recipients,
                admission: None,
                network_error: None,
            };
            match sent {
                Ok(Ok(result)) => outcome.admission = Some(report(result)),
                Ok(Err(error)) => outcome.network_error = Some(error.to_string()),
                Err(_) => {
                    outcome.network_error =
                        Some("publication deadline exceeded; outcome may be partial".into())
                }
            }
            value.publication = Some(outcome);
        }
        WorkspaceTransition::Management(action, commit) => {
            value.step = Some(membership::step_json(
                &arachne_security::MembershipAuthorization::Management(action),
                &commit,
            ));
        }
        WorkspaceTransition::Invitation(invitation, checkpoint, action, commit) => {
            let issued =
                invitation_envelope(session, &invitation, checkpoint).map_err(errors::legacy)?;
            let mut step = membership::step_json(
                &arachne_security::MembershipAuthorization::Management(action),
                &commit,
            );
            step["invitation_checkpoint"] = json!({
                "grant": invitation.public_grant(),
                "checkpoint": issued["checkpoint"],
            });
            value.issued_invitation = Some(issued);
            value.step = Some(step);
        }
        WorkspaceTransition::Admission => {
            let admitted = std::mem::take(&mut session.admission.in_flight);
            let mut delivered = 0usize;
            let mut pushed = 0usize;
            if let Some(workspace) = session.workspace.clone() {
                for attempt in &admitted {
                    let held = session.admission.waiters.take(&attempt.id());
                    let checkpoint = held
                        .as_ref()
                        .and_then(|(_, checkpoint)| checkpoint.as_deref());
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
                            let delivered =
                                !exchange.expired() && exchange.respond(reply.clone()).is_ok();
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
            value.results_delivered = Some(delivered);
            value.results_pushed = Some(pushed);
        }
        WorkspaceTransition::WorkspaceName => {}
        WorkspaceTransition::Join => {
            session.join.pending = None;
            session.join.lifecycle = None;
            session.join.history_prefix.clear();
            transition_activity(session, WorkspacePhase::Active, None)?;
        }
    }
    if joined && session.transition.inbound.is_some() {
        let reply = send_inbound_admission_reply(session)?;
        value.reply_queued = Some(reply.queued);
    }
    if let Some(id) = staged_approval_id {
        session.admission.pending_approvals.remove(&id);
        session.admission.staged_approval_id = None;
    }
    // A member that just reached the newest head it heard announces it
    // too, so members that are behind pull from many members.
    let reached_head = received
        && session.workspace.as_ref().is_some_and(|owner| {
            !session.membership.steps_ahead.contains_key(&owner.epoch())
                && session
                    .membership
                    .head
                    .as_ref()
                    .is_none_or(|(head, _)| *head <= owner.epoch())
        });
    if committed_here || reached_head {
        membership::announce_head(session);
    }
    value.activity = activity_view(session);
    Ok(AdoptReply::Adopted(Box::new(value)))
}
