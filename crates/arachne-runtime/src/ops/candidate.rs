//! The adopt step of the stage → save → adopt lifecycle, shared by every
//! group: admission and management, join, publication, reception, recovery
//! and current view. Each adopt op accepts only its own kind of candidate.

use std::time::Duration;

use arachne_api::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::client::DeliveryReport;
use crate::errors::security;
use crate::ops::admission::{admission_reply_page, queue_admission_push, send_inbound_admission_reply};
use crate::session::{activity_view, commit_workspace, transition_activity};
use crate::workspace_activity::ActivityView;
use crate::ops::invitation::invitation_envelope;
use crate::{Session, WorkspacePhase, WorkspaceTransition, membership, persistence, report};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdoptArgs {
    /// The opaque token the stage op returned.
    pub candidate: Vec<u8>,
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

/// The exact kind of a staged candidate. A typed candidate carries the kinds
/// its adopt method accepts, so a candidate of one kind never adopts as
/// another (for example an admission as an invitation or a removal).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateKind {
    Admission,
    Management,
    WorkspaceName,
    Invitation,
    Removal,
    Join,
    Publication,
    Reception,
    Recovery,
    CurrentView,
}

impl CandidateKind {
    fn of(transition: &WorkspaceTransition) -> Self {
        match transition {
            WorkspaceTransition::Admission => CandidateKind::Admission,
            WorkspaceTransition::Management(..) => CandidateKind::Management,
            WorkspaceTransition::WorkspaceName => CandidateKind::WorkspaceName,
            WorkspaceTransition::Invitation(..) => CandidateKind::Invitation,
            WorkspaceTransition::Join => CandidateKind::Join,
            WorkspaceTransition::RoutedPublication(..) => CandidateKind::Publication,
            WorkspaceTransition::Inbox | WorkspaceTransition::InboxRejected => {
                CandidateKind::Reception
            }
            WorkspaceTransition::InboxRecovery { .. } | WorkspaceTransition::DirectMiss { .. } => {
                CandidateKind::Recovery
            }
            WorkspaceTransition::CurrentView { .. } => CandidateKind::CurrentView,
        }
    }

    /// The adopt op family of this kind.
    fn family(self) -> AdoptKind {
        match self {
            CandidateKind::Admission
            | CandidateKind::Management
            | CandidateKind::WorkspaceName
            | CandidateKind::Invitation
            | CandidateKind::Removal => AdoptKind::Admission,
            CandidateKind::Join => AdoptKind::Join,
            CandidateKind::Publication => AdoptKind::Publication,
            CandidateKind::Reception => AdoptKind::Reception,
            CandidateKind::Recovery => AdoptKind::Recovery,
            CandidateKind::CurrentView => AdoptKind::CurrentView,
        }
    }
}

/// The staged candidate: its exact kind and token.
pub(crate) fn staged(session: &Session) -> Option<(CandidateKind, &[u8])> {
    if let Some((_, token)) = &session.transition.removal {
        return Some((CandidateKind::Removal, token));
    }
    session
        .transition
        .staged
        .as_ref()
        .map(|staged| (CandidateKind::of(&staged.transition), staged.snapshot.as_slice()))
}

fn kind_mismatch() -> ApiError {
    ApiError::wrong_state("candidate kind does not match this adopt operation")
}

/// Adopt `token` only if the staged candidate is exactly one of `kinds`.
/// Every check runs before anything changes.
pub(crate) fn adopt_exact(
    session: &mut Session,
    kinds: &[CandidateKind],
    token: Vec<u8>,
) -> Result<AdoptReply, ApiError> {
    let (kind, staged_token) = staged(session)
        .ok_or_else(|| ApiError::candidate_stale("candidate is no longer staged"))?;
    if staged_token != token.as_slice() {
        return Err(ApiError::candidate_stale("candidate is no longer staged"));
    }
    if !kinds.contains(&kind) {
        return Err(kind_mismatch());
    }
    adopt(session, kind.family(), token)
}

/// Drop the staged candidate `token`. `false` when it is no longer staged.
/// A candidate already in storage, or a removal, cannot be discarded.
pub(crate) fn discard(session: &mut Session, token: &[u8]) -> Result<bool, ApiError> {
    match staged(session) {
        Some((CandidateKind::Removal, staged)) if staged == token => Err(ApiError::wrong_state(
            "removed membership awaits durable adoption",
        )),
        Some((_, staged)) if staged == token => {
            Ok(crate::ops::workspace::discard_candidate(session)?.discarded)
        }
        _ => Ok(false),
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiscardArgs {
    pub candidate: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct DiscardReply {
    pub discarded: bool,
}

pub(crate) fn discard_candidate(
    session: &mut Session,
    args: DiscardArgs,
) -> Result<DiscardReply, ApiError> {
    Ok(DiscardReply {
        discarded: discard(session, &args.candidate)?,
    })
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
    pub issued_invitation: Option<crate::client::InvitationInfo>,
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
    adopt(session, AdoptKind::Admission, args.candidate)
}

pub(crate) fn adopt_join(session: &mut Session, args: AdoptArgs) -> Result<AdoptReply, ApiError> {
    adopt(session, AdoptKind::Join, args.candidate)
}

pub(crate) fn adopt_publication(
    session: &mut Session,
    args: AdoptArgs,
) -> Result<AdoptReply, ApiError> {
    adopt(session, AdoptKind::Publication, args.candidate)
}

pub(crate) fn adopt_reception(session: &mut Session, args: AdoptArgs) -> Result<AdoptReply, ApiError> {
    adopt(session, AdoptKind::Reception, args.candidate)
}

pub(crate) fn adopt_recovery(session: &mut Session, args: AdoptArgs) -> Result<AdoptReply, ApiError> {
    adopt(session, AdoptKind::Recovery, args.candidate)
}

pub(crate) fn adopt_current_view(
    session: &mut Session,
    args: AdoptArgs,
) -> Result<AdoptReply, ApiError> {
    adopt(session, AdoptKind::CurrentView, args.candidate)
}

/// Adopt the staged candidate of `kind`: the one place a staged candidate or
/// a staged removal becomes committed. Core saves it to record storage and
/// reads it back first; only then does live state move.
pub(crate) fn adopt(
    session: &mut Session,
    kind: AdoptKind,
    snapshot: Vec<u8>,
) -> Result<AdoptReply, ApiError> {
    if let Some((_, expected)) = &session.transition.removal {
        // The guards let only adopt_admission through while a removal waits.
        if kind != AdoptKind::Admission {
            return Err(kind_mismatch());
        }
        if &snapshot != expected {
            return Err(ApiError::candidate_stale(
                "removed snapshot does not match candidate",
            ));
        }
        persistence::commit_candidate(session, &snapshot)?;
        let (removed, _) = session.transition.removal.as_ref().unwrap();
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
        return Err(kind_mismatch());
    }
    if snapshot != staged.snapshot {
        return Err(ApiError::candidate_stale(
            "workspace snapshot does not match candidate",
        ));
    }
    persistence::commit_candidate(session, &snapshot)?;
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
        durable: true,
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
    // B7f-1: direct sequences this step gave up (B7e), reported on the
    // adoption as on the staging reply.
    let missed = crate::ops::publication::missed_since_commit(session, staged.inbox.as_ref());
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
            // The send (and its gossip join) also ends at the op deadline.
            let send_limit = crate::deadline::cap(session.op_deadline, Duration::from_secs(10));
            let sent = session.runtime.block_on(async {
                tokio::time::timeout(send_limit, async {
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
            let issued = invitation_envelope(session, &invitation, checkpoint)?;
            let mut step = membership::step_json(
                &arachne_security::MembershipAuthorization::Management(action),
                &commit,
            );
            step["invitation_checkpoint"] = json!({
                "grant": invitation.public_grant(),
                "checkpoint": issued.checkpoint,
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
    if value.missing_count.is_none() {
        value.missing_count = missed;
    }
    value.activity = activity_view(session);
    Ok(AdoptReply::Adopted(Box::new(value)))
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn discard_returns_a_staged_admission_batch_to_intake() {
        let owner = arachne_security::Workspace::create([107; 32], "Owner").unwrap();
        let mut session = crate::membership::bare_test_session(owner);
        let staged = crate::ops::management::stage_workspace_name(
            &mut session,
            crate::ops::management::WorkspaceNameArgs {
                workspace_name: "Named".into(),
            },
        )
        .unwrap();
        // As if the staged step also carried an admission batch and approval.
        session.admission.in_flight =
            vec![arachne_security::AdmissionAttempt::new([1; 32], vec![1]).unwrap()];
        session.admission.staged_approval_id = Some([2; 32]);
        assert!(!super::discard(&mut session, &[0; 37]).unwrap());
        assert!(super::discard(&mut session, &staged.snapshot).unwrap());
        // A retried request is assessed again instead of waiting for ever.
        assert!(session.admission.in_flight.is_empty());
        assert!(session.admission.staged_approval_id.is_none());
    }

    #[test]
    fn removal_is_not_delayed_by_pending_objects_and_delivery_state_carries() {
        use arachne_delivery::{
            PublisherLog,
            inbox::{InboxStage, ObjectInbox},
        };
        use arachne_routing::PublicationContext;
        use arachne_security::{PendingJoin, Workspace};

        let root = [105; 32];
        let provider = arachne_store::MemoryProvider::default();
        let handle = create(Some(&root)).unwrap();
        attach_storage(handle, StorageConfig::memory(&provider)).unwrap();
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
        harness::seed_workspace(&provider, &admin, Some(&publisher), Some(&inbox)).unwrap();
        call(json!({"op":"restore_workspace","workspace":admin.id()})).unwrap();
        let pending = call(json!({"op":"poll_pending_object"})).unwrap();
        assert_eq!(pending["payload"], json!(b"still pending"));

        // The removal stages and adopts while the object is still pending.
        let staged = call(json!({"op":"stage_management",
            "action":{"kind":"remove","member":sender.member().unwrap().id()}}))
        .unwrap();
        let adopted =
            call(json!({"op":"adopt_admission","candidate":staged["candidate"]})).unwrap();
        assert_eq!(adopted["epoch"], admin.epoch() + 1);
        assert_eq!(adopted["members"], 1);
        // The pending object is carried into the new epoch and survives restart.
        assert_eq!(call(json!({"op":"poll_pending_object"})).unwrap(), pending);
        close(handle).unwrap();
        let handle = create(Some(&root)).unwrap();
        attach_storage(handle, StorageConfig::memory(&provider)).unwrap();
        let call = |request: Value| -> Result<Value, String> {
            serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
                .map_err(|error| error.to_string())
        };
        call(json!({"op":"restore_workspace","workspace":admin.id()})).unwrap();
        assert_eq!(call(json!({"op":"poll_pending_object"})).unwrap(), pending);
        let acknowledged = call(json!({"op":"stage_object_acknowledgement",
            "member":pending["member"], "topic":pending["topic"],
            "counter":pending["counter"], "id":pending["id"]}))
        .unwrap();
        call(json!({"op":"adopt_reception","candidate":acknowledged["candidate"]})).unwrap();
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
}
