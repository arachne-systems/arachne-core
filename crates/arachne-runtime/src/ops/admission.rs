//! Owner-side admission: the control drain (`poll_admission`), the admission
//! queue and batch staging, approvals, retained replies and their wire
//! packets, and the owner host tick (`drive_workspace`).

use std::net::SocketAddr;

use arachne_api::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::client::{AdmissionAuthorization, AdmissionReply};
use crate::errors::{self, security};
use crate::membership::{self, JoinStep};
use crate::ops::{self, Op, candidate, management};
use crate::session::{activity_value, carry_delivery, check_epoch_transition, seal_state};
use crate::{
    MAX_RUNTIME_ADMISSION_BATCH, PendingAdmissionApproval, PendingControl, QueuedAdmission, Session, StagedWorkspace,
    WorkspaceTransition, admission_state, persistence, presence,
};
use crate::ops::join::{INVITATION_CHECKPOINT_REQUEST, invitation_checkpoint_reply};
use crate::ops::nearby::{
    NEARBY_IDENTITY, NEARBY_INVITATION, NEARBY_WORKSPACE, nearby_workspace_reply,
};

/// Queued control requests scanned for a range pull on each poll.
const RANGE_SCAN_DEPTH: usize = 64;

// Versioned admission transport wrapper. A raw local request carries no
// history pin. `DFJA\x03` pins history: the checkpoint is never sent, since the
// request's grant already names its digest and the responder resolves the
// checkpoint from its own state (B3a). The bool says whether history is pinned.
pub(crate) type AdmissionPacket<'a> = (&'a [u8], bool, Option<&'a str>);

pub(crate) const ADMISSION_PACKET: &[u8; 5] = b"DFJA\x03";
pub(crate) const ADMISSION_HISTORY_PAGE_REQUEST: &[u8; 5] = b"DFJP\x02";
const ADMISSION_RESULT_OFFER: &[u8; 5] = b"DFAR\x01";

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

/// An admission candidate that awaits the host's save.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct StagedAdmission {
    pub workspace: [u8; 32],
    pub snapshot: Vec<u8>,
    pub state: &'static str,
    pub durable: bool,
    pub admissions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued: Option<bool>,
}

/// One admission request that waits for an administrator.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ApprovalRow {
    pub attempt_id: [u8; 32],
    pub endpoint: [u8; 32],
    pub request: Vec<u8>,
    pub display_name: Option<String>,
    pub automatic: bool,
    pub delivered: bool,
    pub acknowledged: bool,
}

/// One page of pending approvals.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ApprovalPage {
    pub state: &'static str,
    pub approvals: Vec<ApprovalRow>,
    pub complete: bool,
    pub next_after: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ApprovalAcknowledged {
    pub state: &'static str,
    pub attempt_id: [u8; 32],
    pub acknowledged: bool,
}

/// The reply to a held admission (or leave or offer) exchange.
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct ReplySent {
    pub queued: bool,
    pub remote_receipt: bool,
}

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PollAdmissionArgs {
    /// Report owner-side intake measurement alongside the usual state.
    /// Off by default so the reply shape is unchanged for every caller
    /// that has not asked for it.
    #[serde(default)]
    pub profile: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListApprovalsArgs {
    #[serde(default)]
    pub after: Option<[u8; 32]>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcknowledgeApprovalArgs {
    pub attempt_id: [u8; 32],
}

/// Trusted host seam only: the endpoint must come from authenticated transport.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionArgs {
    pub authenticated_endpoint: [u8; 32],
    pub request: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Ops
// ---------------------------------------------------------------------------

/// Stage one admission from the host. The endpoint must be the
/// authenticated transport identity of the requester.
pub(crate) fn stage(session: &mut Session, args: AdmissionArgs) -> Result<StagedAdmission, ApiError> {
    if !membership::is_administrator(session.workspace.as_deref().ok_or_else(errors::no_workspace)?) {
        return Err(not_administrator());
    }
    stage_admission(
        session,
        args.authenticated_endpoint,
        &args.request,
        None,
        None,
    )
}

/// The retained reply to an admission this owner already committed.
pub(crate) fn retained(session: &mut Session, args: AdmissionArgs) -> Result<AdmissionReply, ApiError> {
    let workspace = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    retained_reply(workspace, args.authenticated_endpoint, &args.request)
}

pub(crate) fn list_approvals(
    session: &mut Session,
    args: ListApprovalsArgs,
) -> Result<ApprovalPage, ApiError> {
    list_pending_approvals(session, args.after, args.limit)
}

pub(crate) fn acknowledge_approval(
    session: &mut Session,
    args: AcknowledgeApprovalArgs,
) -> Result<ApprovalAcknowledged, ApiError> {
    let pending = session
        .admission
        .pending_approvals
        .get_mut(&args.attempt_id)
        .ok_or_else(approval_gone)?;
    pending.acknowledged = true;
    Ok(ApprovalAcknowledged {
        state: admission_state::APPROVAL_PENDING,
        attempt_id: args.attempt_id,
        acknowledged: true,
    })
}

/// Answer the held exchange after its transition is durable.
pub(crate) fn send_reply(session: &mut Session) -> Result<ReplySent, ApiError> {
    send_inbound_admission_reply(session)
}

/// Serve one queued peer control request, or stage the next admission batch.
/// The reply is an open event (typed in ADR step 4 with `Event`).
pub(crate) fn poll(session: &mut Session, args: PollAdmissionArgs) -> Result<Value, ApiError> {
    let profile = args.profile;
    reap_admission_pushes(session);
    // A range pull is a short read of committed steps. Serve it before
    // the rest of the queue: behind a join wave's profile-page queries it
    // waited past the puller's limit (tablets, fix16).
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
    let admission_busy = ops::admission_busy(session);
    // A membership step received by gossip moves this member to the next
    // epoch before anything else is staged.
    if !admission_busy
        && let Some(staged) = membership::stage_gossiped_step(session)?
    {
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
    let incoming = if admission_busy || !session.admission.queue.is_empty() {
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
        // once, when it has nothing else to do.
        return Ok(membership::take_answered(session).unwrap_or(Value::Null));
    };
    if incoming.payload() == NEARBY_IDENTITY {
        incoming
            .respond(
                session
                    .nearby
                    .identity
                    .as_deref()
                    .unwrap_or("Unnamed Arachne device")
                    .as_bytes()
                    .to_vec(),
            )
            .map_err(errors::node)?;
        return Ok(json!({"state":"nearby_identity_replied"}));
    }
    if incoming.payload() == NEARBY_WORKSPACE {
        incoming
            .respond(nearby_workspace_reply(&session.nearby.workspaces))
            .map_err(errors::node)?;
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
        incoming.respond(vec![1]).map_err(errors::node)?;
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
        let value = match membership::receive_leave(session, incoming.peer(), incoming.payload())
        {
            Ok(value) => value,
            Err(_) => {
                let _ = incoming.respond(b"{\"state\":\"leave_denied\"}".to_vec());
                return Ok(json!({"state":"membership_replied"}));
            }
        };
        session.transition.inbound = Some(incoming);
        return Ok(value);
    }
    if incoming.payload().starts_with(b"DFMO") {
        let offered = membership::receive_offer(session, incoming.payload());
        return match offered {
            Ok(value) => {
                session.transition.inbound = Some(incoming);
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
            &membership::lock_profiles(&session.membership.profiles),
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
            .respond(membership::encode_reply(&reply).map_err(ApiError::internal)?)
            .map_err(errors::node)?;
        let mut event = json!({"state":"membership_replied", "remote_receipt":false});
        if current_peer {
            event["peer"] = json!(peer);
        }
        return Ok(event);
    }
    // One control queue: route continuity before admission parsing. Never serve
    // staged state (the dispatcher rejects polls while adoption is pending).
    if ops::recovery::is_query(incoming.payload()) {
        return ops::recovery::serve(session, incoming);
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
    let result: Result<Value, ApiError> = (|| {
        let workspace = session
            .workspace
            .as_ref()
            .ok_or_else(errors::no_workspace)?;
        let (request, pinned) = admission_parts(incoming.payload())?;
        let checkpoint = pinned
            .then(|| pinned_checkpoint(workspace, request))
            .transpose()?;
        let checkpoint = checkpoint.as_deref();
        if let Some(checkpoint) = checkpoint {
            workspace
                .membership_history(incoming.peer(), request, checkpoint)
                .map_err(security(ErrorCode::InvalidInput))?;
        }
        let retained = workspace
            .retained_admission(incoming.peer(), request)
            .map_err(security(ErrorCode::InvalidInput))?
            .is_some();
        let value = if retained {
            json!({"workspace":workspace.id(),"state":"reply_ready"})
        } else {
            serde_json::to_value(stage_admission(
                session,
                incoming.peer(),
                request,
                checkpoint,
                None,
            )?)
            .map_err(errors::encode)?
        };
        Ok(value)
    })();
    let value = match result {
        Ok(value) => value,
        Err(error) => {
            let feedback = admission_feedback(error.message());
            let reason = feedback["reason"]
                .as_str()
                .ok_or_else(|| ApiError::internal("admission feedback has no reason"))?;
            // An invalid/unapproved request is not a failure of the member's
            // accepted workspace. Reply without exposing details or stopping it.
            let approval = if reason == "approval_required" || reason == "automatic_approval_required"
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
            let _ = incoming.respond(serde_json::to_vec(&feedback).map_err(|_| {
                ApiError::internal("admission feedback encoding failed")
            })?);
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
    session.transition.inbound = Some(incoming);
    Ok(value)
}

/// Drive one ordered workspace transition. With native record storage, Rust
/// persists and adopts its candidate before answering a peer; hosts receive
/// only the resulting projection. The reply is an open event (step 4).
pub(crate) fn drive_workspace(session: &mut Session) -> Result<Value, ApiError> {
    if live(session)?.records.is_none() {
        return Err(ApiError::wrong_state(
            "workspace lifecycle requires native record storage",
        ));
    }
    let mut staged = ops::nested(session, Op::PollAdmission, |session| {
        poll(session, PollAdmissionArgs { profile: false })
    })?;
    let staged_state = staged
        .get("state")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if staged_state.as_deref() != Some("awaiting_save") {
        if staged_state.as_deref() == Some("reply_ready") && live(session)?.transition.inbound.is_some()
        {
            let reply = ops::nested(session, Op::SendAdmissionReply, send_reply)?;
            staged["state"] = json!("workspace_reply_ready");
            staged["reply_queued"] = json!(reply.queued);
        }
        // Return the event just drained before attempting optional
        // membership reconciliation. A presence/admission reply is the
        // authoritative result for this host tick; an unrelated query
        // may still be in flight or have reached its own transport
        // deadline and must not hide it.
        if staged_state.is_some() {
            staged["activity"] = activity_value(live(session)?);
            return Ok(staged);
        }
        let membership = ops::nested(live_mut(session)?, Op::PollMembershipUpdate, |session| {
            ops::membership::poll_update(session)
        })?;
        if !membership.is_null() {
            let state = membership
                .get("state")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if matches!(
                state.as_deref(),
                Some("workspace_name_update_available" | "workspace_name_checkpoint_available")
            ) {
                let staged_name = if state.as_deref() == Some("workspace_name_update_available") {
                    let name_record = serde_json::from_value(membership["name_record"].clone())
                        .map_err(|_| ApiError::internal("workspace name record is invalid"))?;
                    ops::nested(live_mut(session)?, Op::StageWorkspaceNameUpdate, |session| {
                        management::stage_workspace_name_update(
                            session,
                            management::WorkspaceNameUpdateArgs { name_record },
                        )
                    })?
                } else {
                    let name_checkpoint =
                        serde_json::from_value(membership["name_checkpoint"].clone()).map_err(
                            |_| ApiError::internal("workspace name checkpoint is invalid"),
                        )?;
                    ops::nested(live_mut(session)?, Op::StageWorkspaceNameCheckpoint, |session| {
                        management::stage_workspace_name_checkpoint(
                            session,
                            management::WorkspaceNameCheckpointArgs { name_checkpoint },
                        )
                    })?
                };
                let snapshot = staged_name.snapshot;
                persistence::commit_candidate(live_mut(session)?, &snapshot)
                    ?;
                let mut committed = adopt_admission_value(session, snapshot)?;
                committed["state"] = json!("workspace_name_committed");
                committed["activity"] = activity_value(live(session)?);
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
            membership["activity"] = activity_value(live(session)?);
            return Ok(membership);
        }
        staged["activity"] = activity_value(live(session)?);
        return Ok(staged);
    }
    let snapshot: Vec<u8> = serde_json::from_value(staged["snapshot"].clone())
        .map_err(|_| ApiError::internal("workspace candidate snapshot is invalid"))?;
    persistence::commit_candidate(live_mut(session)?, &snapshot)?;
    let mut committed = adopt_admission_value(session, snapshot)?;
    if live(session)?.transition.inbound.is_some() {
        let reply = ops::nested(session, Op::SendAdmissionReply, send_reply)?;
        committed["reply_queued"] = json!(reply.queued);
    }
    committed["state"] = json!("workspace_committed");
    committed["activity"] = activity_value(live(session)?);
    Ok(committed)
}

/// Adopt the saved admission candidate as an inner op of a drive op.
fn adopt_admission_value(session: &mut Session, snapshot: Vec<u8>) -> Result<Value, ApiError> {
    let session = live_mut(session)?;
    let adopted = ops::nested(session, Op::AdoptAdmission, |session| {
        candidate::adopt_admission(session, candidate::AdoptArgs { snapshot })
    })?;
    serde_json::to_value(adopted).map_err(errors::encode)
}

/// The session, unless an inner op ended it (a removal was adopted).
pub(crate) fn live(session: &Session) -> Result<&Session, ApiError> {
    if session.ending {
        return Err(errors::closed());
    }
    Ok(session)
}

pub(crate) fn live_mut(session: &mut Session) -> Result<&mut Session, ApiError> {
    if session.ending {
        return Err(errors::closed());
    }
    Ok(session)
}

// ---------------------------------------------------------------------------
// Staging and retained replies
// ---------------------------------------------------------------------------

pub(crate) fn stage_admission(
    session: &mut Session,
    authenticated_endpoint: [u8; 32],
    request: &[u8],
    checkpoint: Option<&[u8]>,
    validated: Option<&arachne_security::ValidatedAdmission>,
) -> Result<StagedAdmission, ApiError> {
    check_epoch_transition(session)?;
    let workspace = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    if workspace
        .retained_admission(authenticated_endpoint, request)
        .map_err(security(ErrorCode::InvalidInput))?
        .is_some()
    {
        return Err(ApiError::wrong_state(
            "admission already retained; retrieve its existing response",
        ));
    }
    let prepared = match validated {
        Some(validated) => workspace
            .prepare_validated_admission(authenticated_endpoint, request, validated)
            .map_err(security(ErrorCode::InvalidInput))?,
        None => workspace
            .prepare_admission(authenticated_endpoint, request)
            .map_err(security(ErrorCode::InvalidInput))?,
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
) -> Result<StagedAdmission, ApiError> {
    let key = session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    let (publisher, inbox) = carry_delivery(session, &workspace)?;
    let snapshot = seal_state(
        session.records.is_some(),
        &workspace,
        key,
        publisher.as_ref(),
        inbox.as_ref(),
    )?;
    let value = StagedAdmission {
        workspace: workspace.id(),
        snapshot: snapshot.clone(),
        state: "awaiting_save",
        durable: false,
        admissions: admission_count,
        queued: None,
    };
    session.transition.staged = Some(StagedWorkspace {
        inbox,
        publisher,
        transition: WorkspaceTransition::Admission,
        workspace,
        snapshot,
    });
    Ok(value)
}

pub(crate) fn retained_reply(
    workspace: &arachne_security::Workspace,
    authenticated_endpoint: [u8; 32],
    request: &[u8],
) -> Result<AdmissionReply, ApiError> {
    let reply = workspace
        .retained_admission(authenticated_endpoint, request)
        .map_err(security(ErrorCode::InvalidInput))?
        .ok_or_else(|| ApiError::wrong_state("no retained admission"))?;
    Ok(AdmissionReply {
        workspace: workspace.id(),
        epoch: reply.epoch,
        commit: reply.commit,
        welcome: reply.welcome,
        authorization: AdmissionAuthorization {
            invitation_key: reply.authorization.invitation_key,
            grant_signature: reply.authorization.grant_signature.to_vec(),
            redemption_signature: reply.authorization.redemption_signature.to_vec(),
        },
    })
}

fn admission_reply(
    workspace: &arachne_security::Workspace,
    peer: [u8; 32],
    request: &[u8],
    checkpoint: Option<&[u8]>,
) -> Result<Vec<u8>, ApiError> {
    admission_reply_page(workspace, peer, request, checkpoint, 0)
}

pub(crate) fn admission_reply_page(
    workspace: &arachne_security::Workspace,
    peer: [u8; 32],
    request: &[u8],
    checkpoint: Option<&[u8]>,
    offset: usize,
) -> Result<Vec<u8>, ApiError> {
    let reply =
        serde_json::to_value(retained_reply(workspace, peer, request)?).map_err(errors::encode)?;
    if let Some(checkpoint) = checkpoint {
        let mut steps = workspace
            .membership_history(peer, request, checkpoint)
            .map_err(security(ErrorCode::InvalidInput))?;
        let last = steps
            .iter()
            .position(|(_, commit)| json!(commit) == reply["commit"])
            .ok_or_else(|| ApiError::internal("retained admission missing from verified history"))?;
        steps.truncate(last + 1); // Retry may follow later Adds; Welcome pins this exact step.
        if offset >= steps.len() {
            return Err(page_offset_out_of_bounds());
        }
        let steps: Vec<Value> = steps
            .iter()
            .map(|(authorization, commit)| membership::step_json(authorization, commit))
            .collect();
        return admission_history_page(reply, &steps, offset, arachne_node::MAX_CONTROL_REPLY);
    }
    let encoded = serde_json::to_vec(&reply).map_err(errors::encode)?;
    if encoded.len() > arachne_node::MAX_CONTROL_REPLY {
        return Err(reply_too_large("admission reply exceeds transport bound"));
    }
    Ok(encoded)
}

fn page_offset_out_of_bounds() -> ApiError {
    ApiError::invalid_input("offset", "admission history page offset is out of bounds")
}

fn reply_too_large(detail: &str) -> ApiError {
    ApiError::limit_reached(
        "control reply",
        arachne_node::MAX_CONTROL_REPLY as u64,
        detail,
    )
}

/// Fill one admission reply with as many history steps from `offset` as fit
/// in `limit` encoded bytes.
///
/// Each candidate is encoded in its exact final form (every paging field it
/// will carry) and the bytes returned are the bytes measured, so the reply is
/// bounded by construction. B3d: the size used to be checked before
/// `history_page` was added, so a page filled to within 20 bytes of the bound
/// overshot it; random commit bytes (1-3 JSON digits each) moved the fill
/// point, so it failed only sometimes.
fn admission_history_page(
    mut reply: Value,
    steps: &[Value],
    offset: usize,
    limit: usize,
) -> Result<Vec<u8>, ApiError> {
    if offset >= steps.len() {
        return Err(page_offset_out_of_bounds());
    }
    let mut fitted = None;
    for next in offset + 1..=steps.len() {
        reply["commits"] = json!(steps[offset..next]);
        if offset == 0 && next == steps.len() {
            if let Some(object) = reply.as_object_mut() {
                for key in ["history_offset", "history_next", "history_complete", "history_page"] {
                    object.remove(key);
                }
            }
        } else {
            reply["history_offset"] = json!(offset);
            reply["history_next"] = json!(next);
            reply["history_complete"] = json!(next == steps.len());
            reply["history_page"] = json!(true);
        }
        let encoded = serde_json::to_vec(&reply).map_err(errors::encode)?;
        if encoded.len() > limit {
            break;
        }
        fitted = Some(encoded);
    }
    fitted.ok_or_else(|| reply_too_large("admission history step exceeds transport bound"))
}

pub(crate) fn send_inbound_admission_reply(session: &mut Session) -> Result<ReplySent, ApiError> {
    let incoming = session
        .transition
        .inbound
        .take()
        .ok_or_else(|| ApiError::wrong_state("session has no received admission"))?;
    let workspace = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let reply = if incoming.payload().starts_with(b"DFLV") {
        membership::leave_reply(workspace, incoming.peer(), incoming.payload())
            ?
    } else if incoming.payload().starts_with(b"DFMO")
        || incoming.payload().starts_with(ADMISSION_RESULT_OFFER)
    {
        vec![1] // Acknowledge only after the staged transition or verified Welcome is durable.
    } else {
        let (request, pinned) = admission_parts(incoming.payload())?;
        let checkpoint = pinned
            .then(|| pinned_checkpoint(workspace, request))
            .transpose()?;
        admission_reply(workspace, incoming.peer(), request, checkpoint.as_deref())?
    };
    let queued = match incoming.respond(reply) {
        Ok(()) => true,
        Err(arachne_node::Error::Rejected) => false, // Requester expired; saved admission remains retryable.
        Err(error) => return Err(errors::node(error)),
    };
    Ok(ReplySent {
        queued,
        remote_receipt: false,
    })
}

// ---------------------------------------------------------------------------
// Wire packets
// ---------------------------------------------------------------------------

fn bad_packet(reason: &str) -> ApiError {
    ApiError::invalid_input("packet", reason)
}

/// `DFJA\x03 | u32 request length | u16 name length | request | name`.
pub(crate) fn admission_request_packet(request: &[u8], name: &[u8]) -> Result<Vec<u8>, ApiError> {
    let request_len = u32::try_from(request.len())
        .map_err(|_| ApiError::invalid_input("request", "admission request too large"))?;
    let name_len = u16::try_from(name.len())
        .map_err(|_| ApiError::invalid_input("display_name", "admission display name too large"))?;
    let mut packet = ADMISSION_PACKET.to_vec();
    packet.extend(request_len.to_be_bytes());
    packet.extend(name_len.to_be_bytes());
    packet.extend(request);
    packet.extend(name);
    Ok(packet)
}

/// The checkpoint an admission request pins, from this responder's own state.
pub(crate) fn pinned_checkpoint(
    workspace: &arachne_security::Workspace,
    request: &[u8],
) -> Result<Vec<u8>, ApiError> {
    workspace
        .admission_checkpoint(request)
        .map_err(security(ErrorCode::InvalidInput))
}

pub(crate) fn admission_packet(bytes: &[u8]) -> Result<AdmissionPacket<'_>, ApiError> {
    if !bytes.starts_with(b"DFJA") {
        return Ok((bytes, false, None));
    }
    if bytes.len() < 11 || !bytes.starts_with(ADMISSION_PACKET) {
        return Err(bad_packet("invalid admission packet"));
    }
    let length = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
    let (header, name_length) = (
        11usize,
        u16::from_be_bytes(bytes[9..11].try_into().unwrap()) as usize,
    );
    let request_end = header
        .checked_add(length)
        .ok_or_else(|| bad_packet("invalid admission packet bounds"))?;
    let name_end = request_end
        .checked_add(name_length)
        .ok_or_else(|| bad_packet("invalid admission packet bounds"))?;
    if length == 0 || name_end != bytes.len() {
        return Err(bad_packet("invalid admission packet bounds"));
    }
    let name = if name_length == 0 {
        None
    } else {
        let value = std::str::from_utf8(&bytes[request_end..name_end])
            .map_err(|_| bad_packet("invalid admission display name"))?;
        if value.trim() != value
            || value.is_empty()
            || value.len() > 256
            || value.chars().count() > 80
            || value.chars().any(|c| {
                c.is_control()
                    || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            })
        {
            return Err(bad_packet("invalid admission display name"));
        }
        Some(value)
    };
    Ok((&bytes[header..request_end], true, name))
}

pub(crate) fn admission_parts(bytes: &[u8]) -> Result<(&[u8], bool), ApiError> {
    let (request, pinned, _) = admission_packet(bytes)?;
    Ok((request, pinned))
}

/// `DFJP\x02 | u32 request length | u32 offset | request`. No checkpoint.
pub(crate) fn admission_history_page_packet(
    request: &[u8],
    offset: usize,
) -> Result<Vec<u8>, ApiError> {
    let request_len = u32::try_from(request.len())
        .map_err(|_| ApiError::invalid_input("request", "admission request too large"))?;
    let offset = u32::try_from(offset)
        .map_err(|_| ApiError::invalid_input("offset", "history offset too large"))?;
    let mut packet = ADMISSION_HISTORY_PAGE_REQUEST.to_vec();
    packet.extend(request_len.to_be_bytes());
    packet.extend(offset.to_be_bytes());
    packet.extend(request);
    Ok(packet)
}

pub(crate) fn parse_admission_history_page_packet(
    bytes: &[u8],
) -> Result<(&[u8], usize), ApiError> {
    if !bytes.starts_with(ADMISSION_HISTORY_PAGE_REQUEST) || bytes.len() < 13 {
        return Err(bad_packet("invalid admission history page request"));
    }
    let request_len = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
    let offset = u32::from_be_bytes(bytes[9..13].try_into().unwrap()) as usize;
    if request_len == 0 || 13usize.checked_add(request_len) != Some(bytes.len()) {
        return Err(bad_packet("invalid admission history page bounds"));
    }
    Ok((&bytes[13..], offset))
}

pub(crate) fn admission_packet_candidate(bytes: &[u8]) -> bool {
    bytes.starts_with(b"DFJA")
        || bytes.starts_with(b"DFJR\x01")
        || bytes.starts_with(ADMISSION_HISTORY_PAGE_REQUEST)
}

pub(crate) fn admission_offer_candidate(bytes: &[u8]) -> bool {
    bytes.starts_with(ADMISSION_RESULT_OFFER)
}

fn admission_offer_packet(reply: &[u8]) -> Result<Vec<u8>, ApiError> {
    let bound = |detail: &str| ApiError::limit_reached("control request", 32 * 1024, detail);
    let length =
        u32::try_from(reply.len()).map_err(|_| bound("admission result is too large"))?;
    if reply.len() > 32 * 1024 - 9 {
        return Err(bound("admission result offer exceeds control bound"));
    }
    let mut packet = ADMISSION_RESULT_OFFER.to_vec();
    packet.extend(length.to_be_bytes());
    packet.extend(reply);
    Ok(packet)
}

pub(crate) fn parse_admission_offer(packet: &[u8]) -> Result<(Vec<JoinStep>, Vec<u8>), ApiError> {
    if packet.len() < 9 || !packet.starts_with(ADMISSION_RESULT_OFFER) {
        return Err(bad_packet("invalid admission result offer"));
    }
    let length = u32::from_be_bytes(packet[5..9].try_into().unwrap()) as usize;
    if length == 0 || packet.len() != 9 + length || packet.len() > 32 * 1024 {
        return Err(bad_packet("invalid admission result offer bounds"));
    }
    let reply: Value =
        serde_json::from_slice(&packet[9..]).map_err(|_| bad_packet("invalid admission result"))?;
    if reply.get("history_complete").and_then(Value::as_bool) == Some(false) {
        return Err(bad_packet("paged admission result requires the retry path"));
    }
    let commits = if let Some(commits) = reply.get("commits") {
        serde_json::from_value(commits.clone())
            .map_err(|_| bad_packet("invalid admission result commits"))?
    } else {
        vec![
            serde_json::from_value(json!({
                "commit": reply["commit"].clone(),
                "authorization": reply["authorization"].clone(),
            }))
            .map_err(|_| bad_packet("incomplete admission result"))?,
        ]
    };
    if commits.is_empty() || commits.len() > arachne_security::HISTORY_CHUNK_STEPS {
        return Err(bad_packet("admission result history exceeds bounds"));
    }
    let welcome = serde_json::from_value(reply["welcome"].clone())
        .map_err(|_| bad_packet("admission result has no Welcome"))?;
    Ok((commits, welcome))
}

// ---------------------------------------------------------------------------
// Intake queue
// ---------------------------------------------------------------------------

fn reap_admission_pushes(session: &mut Session) {
    session
        .admission
        .pushes
        .retain(|push| !push.task.is_finished());
}

pub(crate) fn queue_admission_push(
    session: &mut Session,
    attempt: &arachne_security::AdmissionAttempt,
    reply: &[u8],
    route: Option<SocketAddr>,
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
    session.admission.pushes.push(PendingControl {
        query: attempt.id(),
        peer,
        task,
    });
    true
}

/// The protocol reason a requester sees, from the security crate's exact
/// texts (the same constants the error table uses).
/// Security error for an Add from a non-administrator (ADR A2 step 2).
const ONLY_ADMINISTRATORS_ADMIT: &str = "only an administrator may admit members";

fn not_administrator() -> ApiError {
    ApiError::not_authorized(
        "Only an administrator can admit members. Ask an administrator of this workspace.",
    )
}

fn admission_reason(error: &str) -> &'static str {
    match error {
        ONLY_ADMINISTRATORS_ADMIT => admission_state::ADMINISTRATOR_REQUIRED,
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
    let result = session.admission.queue.enqueue(attempt)?;
    if result == arachne_security::AdmissionEnqueue::Added {
        session.admission.metadata.insert(
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
    if let Some(overflow) = session.admission.waiters.hold(attempt, incoming, checkpoint) {
        let _ = overflow.respond(b"{\"state\":\"admission_queued\"}".to_vec());
    }
}

fn feedback_bytes(value: &Value) -> Result<Vec<u8>, ApiError> {
    serde_json::to_vec(value).map_err(|_| ApiError::internal("admission feedback encoding failed"))
}

fn queue_admission(
    session: &mut Session,
    incoming: arachne_node::ControlRequest,
) -> Result<Value, ApiError> {
    session.admission.reads_since_stage = session.admission.reads_since_stage.saturating_add(1);
    let peer = incoming.peer();
    let packet = incoming.payload().to_vec();
    if packet.starts_with(ADMISSION_HISTORY_PAGE_REQUEST) {
        let response = match parse_admission_history_page_packet(&packet) {
            Ok((request, offset)) => session.workspace.as_ref().map_or_else(
                || b"{\"state\":\"admission_unavailable\",\"reason\":\"unavailable\"}".to_vec(),
                |workspace| {
                    pinned_checkpoint(workspace, request)
                        .and_then(|checkpoint| {
                            admission_reply_page(workspace, peer, request, Some(&checkpoint), offset)
                        })
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
    // A pinned request names its checkpoint by digest; resolve it from this
    // owner's own state. An unresolvable pin is answered like a bad packet.
    let parsed = admission_packet(&packet).and_then(|(request, pinned, display_name)| {
        let checkpoint = match (pinned, session.workspace.as_ref()) {
            (false, _) => None,
            (true, Some(workspace)) => Some(pinned_checkpoint(workspace, request)?),
            (true, None) => return Err(errors::no_workspace()),
        };
        Ok((request.to_vec(), checkpoint, display_name.map(str::to_owned)))
    });
    let (request, checkpoint, display_name) = match parsed {
        Ok(parsed) => parsed,
        Err(_) => {
            let _ = incoming.respond(feedback_bytes(
                &json!({"state":"admission_unavailable","reason":"unavailable"}),
            )?);
            return Ok(json!({"state":"admission_replied","accepted":false}));
        }
    };
    let attempt = arachne_security::AdmissionAttempt::new(peer, request.clone())
        .map_err(security(ErrorCode::InvalidInput))?;
    {
        let workspace = session
            .workspace
            .as_ref()
            .ok_or_else(errors::no_workspace)?;
        if workspace
            .retained_admission(peer, &request)
            .map_err(security(ErrorCode::InvalidInput))?
            .is_some()
        {
            let reply = admission_reply_page(workspace, peer, &request, checkpoint.as_deref(), 0)?;
            let accepted = incoming.respond(reply).is_ok();
            if accepted {
                session
                    .admission
                    .in_flight
                    .retain(|queued| queued != &attempt);
            }
            return Ok(json!({"state":"admission_replied", "accepted":accepted}));
        }
    }
    // Only administrators admit (ADR A2 section 7). Refuse before the
    // request is queued or held for approval: a queued request would fail
    // at staging and be retried forever. There is no forward path; the
    // joiner asks its next member.
    if !membership::is_administrator(session.workspace.as_deref().ok_or_else(errors::no_workspace)?) {
        let _ = incoming.respond(feedback_bytes(&json!({
            "state": admission_state::UNAVAILABLE,
            "reason": admission_state::ADMINISTRATOR_REQUIRED,
        }))?);
        return Ok(json!({"state":admission_state::REPLIED,"accepted":false,
            "reason":admission_state::ADMINISTRATOR_REQUIRED}));
    }
    if session.admission.queue.contains(&attempt)
        || session
            .admission
            .in_flight
            .iter()
            .any(|queued| queued == &attempt)
    {
        hold_admission_exchange(session, attempt.id(), incoming, checkpoint);
        return Ok(json!({"state":"admission_queued"}));
    }

    let assessment = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?
        .assess_admission(peer, &request);
    if session.admission.pending_approvals.contains_key(&attempt.id()) {
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
        session.admission.pending_approvals.remove(&attempt.id());
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
            let _ = incoming.respond(feedback_bytes(&feedback)?);
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
            .ok_or_else(errors::no_workspace)?
            // Intake only needs to know the pinned history is servable. The
            // transitions themselves are built once, on the reply path, rather
            // than materialized and discarded for every arriving request.
            .check_membership_history(peer, &request, checkpoint)
            .is_err()
    {
        let _ = incoming.respond(feedback_bytes(
            &json!({"state":"admission_unavailable","reason":"unavailable"}),
        )?);
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
    !session.admission.queue.is_empty()
        && (session.admission.queue.len() >= MAX_RUNTIME_ADMISSION_BATCH
            || session.admission.reads_since_stage >= MAX_RUNTIME_ADMISSION_BATCH)
}

fn stage_queued_admission(session: &mut Session) -> Result<Option<Value>, ApiError> {
    session.admission.reads_since_stage = 0;
    let mut ready = Vec::new();
    let mut deferred = Vec::new();
    while ready.len() < MAX_RUNTIME_ADMISSION_BATCH {
        let Some(attempt) = session.admission.queue.pop() else {
            break;
        };
        let Some(queued) = session.admission.metadata.remove(&attempt.id()) else {
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
            .admission
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
        .ok_or_else(errors::no_workspace)?
        .prepare_validated_admission_batch(&inputs)
    {
        Ok(prepared) => prepared,
        Err(error) => {
            for (attempt, queued) in ready {
                requeue_admission(session, attempt, queued)?;
            }
            return Err(security(ErrorCode::InvalidInput)(error));
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
    session.admission.in_flight = attempts;
    value.queued = Some(true);
    Ok(Some(serde_json::to_value(value).map_err(errors::encode)?))
}

fn requeue_admission(
    session: &mut Session,
    attempt: arachne_security::AdmissionAttempt,
    queued: QueuedAdmission,
) -> Result<(), ApiError> {
    let id = attempt.id();
    session
        .admission
        .queue
        .enqueue(attempt)
        .map_err(|_| ApiError::capacity_exceeded("admission queue", 0, "admission queue is full"))?;
    session.admission.metadata.insert(id, queued);
    Ok(())
}

fn approval_gone() -> ApiError {
    ApiError::wrong_state("admission approval is no longer pending")
}

pub(crate) fn pending_approval_id(
    session: &Session,
    request: &[u8],
    requested: Option<[u8; 32]>,
) -> Result<Option<[u8; 32]>, ApiError> {
    if let Some(id) = requested {
        let pending = session
            .admission
            .pending_approvals
            .get(&id)
            .ok_or_else(approval_gone)?;
        if pending.attempt.request() != request {
            return Err(ApiError::invalid_input(
                "attempt_id",
                "admission approval request does not match attempt",
            ));
        }
        return Ok(Some(id));
    }
    Ok(session
        .admission
        .pending_approvals
        .iter()
        .find(|(_, pending)| pending.attempt.request() == request)
        .map(|(id, _)| *id))
}

fn list_pending_approvals(
    session: &Session,
    after: Option<[u8; 32]>,
    limit: Option<usize>,
) -> Result<ApprovalPage, ApiError> {
    let limit = limit.unwrap_or(64);
    if !(1..=64).contains(&limit) {
        return Err(ApiError::invalid_input(
            "limit",
            "approval page limit must be between 1 and 64",
        ));
    }
    let rows: Vec<_> = session
        .admission
        .pending_approvals
        .iter()
        .filter(|(id, _)| after.is_none_or(|after| **id > after))
        .take(limit + 1)
        .collect();
    let complete = rows.len() <= limit;
    let approvals: Vec<ApprovalRow> = rows
        .into_iter()
        .take(limit)
        .map(|(id, pending)| ApprovalRow {
            attempt_id: *id,
            endpoint: pending.attempt.endpoint(),
            request: pending.attempt.request().to_vec(),
            display_name: pending.queued.display_name.clone(),
            automatic: pending.queued.approval_automatic.unwrap_or(false),
            delivered: pending.delivered,
            acknowledged: pending.acknowledged,
        })
        .collect();
    let next_after = approvals.last().map(|row| row.attempt_id);
    Ok(ApprovalPage {
        state: admission_state::APPROVAL_PENDING,
        approvals,
        complete,
        next_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::*;

    #[test]
    fn admission_packet_rejects_invalid_version_and_lengths() {
        let packet = admission_request_packet(&[7], b"").unwrap();
        assert_eq!(admission_parts(&packet).unwrap(), (&[7][..], true));
        let named = admission_request_packet(&[7], b"Alex").unwrap();
        assert_eq!(
            admission_packet(&named).unwrap(),
            (&[7][..], true, Some("Alex"))
        );
        // No checkpoint rides along; trailing bytes are rejected.
        assert!(admission_packet(&[named.as_slice(), &[8]].concat()).is_err());
        for length in 4..packet.len() {
            assert!(admission_parts(&packet[..length]).is_err());
        }
        for length in [0, 2, u32::MAX] {
            let mut bad = packet.clone();
            bad[5..9].copy_from_slice(&length.to_be_bytes());
            assert!(admission_parts(&bad).is_err());
        }
        // Earlier versions embedded the checkpoint; they are not decoded.
        for version in [1, 2] {
            let mut bad = packet.clone();
            bad[4] = version;
            assert!(admission_parts(&bad).is_err());
        }
        let page = admission_history_page_packet(&[7, 8], 3).unwrap();
        assert_eq!(
            parse_admission_history_page_packet(&page).unwrap(),
            (&[7, 8][..], 3)
        );
        assert!(parse_admission_history_page_packet(&[page.as_slice(), &[9]].concat()).is_err());
    }

    /// B3d: every admission history page must fit the byte limit it was
    /// filled against, whatever fill point the (random) commit bytes land on.
    /// Sweeping the limit byte by byte forces every fill point, including one
    /// that leaves less room than the fields added after the size check.
    #[test]
    fn every_admission_history_page_fits_its_limit_at_every_fill_point() {
        let reply = json!({"workspace":(vec![7_u8; 32]), "epoch":42_u64, "commit":(vec![200_u8; 40]),
            "welcome":(vec![9_u8; 64]), "authorization":{"invitation_key":(vec![1_u8; 32]),
            "grant_signature":(vec![2_u8; 64]), "redemption_signature":(vec![3_u8; 64])}});
        let steps: Vec<Value> = (0..12_usize)
            .map(|index| {
                let commit: Vec<u8> = (0..40 + index * 23)
                    .map(|byte| ((byte * 37 + index * 11) % 256) as u8)
                    .collect();
                json!({"commit":commit, "authorization":{"invitation_key":(vec![index as u8; 32])}})
            })
            .collect();
        let whole = serde_json::to_vec(&{
            let mut whole = reply.clone();
            whole["commits"] = json!(steps);
            whole
        })
        .unwrap()
        .len();
        for offset in [0, 3] {
            for limit in 200..whole + 64 {
                let encoded = match admission_history_page(reply.clone(), &steps, offset, limit) {
                    Ok(encoded) => encoded,
                    Err(error) => {
                        assert_eq!(
                            error.message(),
                            "admission history step exceeds transport bound",
                            "offset={offset} limit={limit}"
                        );
                        assert_eq!(error.code(), ErrorCode::LimitReached);
                        continue;
                    }
                };
                assert!(
                    encoded.len() <= limit,
                    "offset={offset} limit={limit}: page of {} bytes overshoots by {}",
                    encoded.len(),
                    encoded.len() - limit
                );
                let page: Value = serde_json::from_slice(&encoded).unwrap();
                let carried = page["commits"].as_array().unwrap();
                assert_eq!(carried[..], steps[offset..offset + carried.len()]);
                if page.get("history_page").is_some() {
                    assert_eq!(page["history_page"], json!(true));
                    assert_eq!(page["history_offset"], json!(offset));
                    let next = page["history_next"].as_u64().unwrap() as usize;
                    assert!(next > offset, "offset={offset} limit={limit}: no progress");
                    assert_eq!(next, offset + carried.len());
                    assert_eq!(page["history_complete"], json!(next == steps.len()));
                } else {
                    assert_eq!(offset, 0);
                    assert_eq!(carried.len(), steps.len());
                    for key in ["history_offset", "history_next", "history_complete"] {
                        assert!(page.get(key).is_none(), "unpaged reply carries {key}");
                    }
                }
            }
        }
    }

    #[test]
    fn bad_packets_are_invalid_input() {
        assert_eq!(
            admission_packet(b"DFJA\x01xxxxxxxxxx").unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            parse_admission_offer(b"DFAR\x01").err().map(|error| error.code()),
            Some(ErrorCode::InvalidInput)
        );
    }

    #[test]
    fn admission_batch_wire_sizes_fit_transport_bounds() {
        use arachne_security::{
            AdmissionAssessment, MembershipAuthorization, PendingJoin, Workspace,
        };

        for count in [8, MAX_RUNTIME_ADMISSION_BATCH] {
            let endpoint = |index: usize| crate::test_endpoint(index as u64);
            let key = |index: usize| crate::test_key(index as u64);
            let mut owner = Workspace::create(key(10_000), "Wire-size owner").unwrap();
            let (registered, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
            owner = registered.workspace;
            let mut joins = Vec::with_capacity(count);
            let mut requests = Vec::with_capacity(count);
            let mut validated = Vec::with_capacity(count);
            for index in 0..count {
                let join = PendingJoin::from_invitation(
                    &invitation,
                    &checkpoint,
                    key(index + 20_000),
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
        let endpoint = |index: usize| crate::test_endpoint(index as u64);
        let key = |index: usize| crate::test_key(index as u64);
        let mut owner = Workspace::create(key(10_000), "500-member owner").unwrap();
        let (registered, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
        owner = registered.workspace;
        let mut joins = Vec::with_capacity(500);
        let mut requests = Vec::with_capacity(500);
        let mut validated = Vec::with_capacity(500);
        for index in 0..500 {
            let remote = endpoint(index + 20_000);
            let join =
                PendingJoin::from_invitation(&invitation, &checkpoint, key(index + 20_000), "Burst member")
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
            let (authorization, commit) = step.parts().unwrap();
            proof.apply_transition(&authorization, &commit).unwrap();
        }
        let joined = target.prepare_workspace(&proof, &welcome).unwrap();
        assert_eq!(joined.member_count(), 501);
        println!(
            "admission_runtime_capacity members=500 batches={batches} pages={pages} elapsed_ms={} page_ms={page_ms:.1?} page_bytes={page_bytes:?}",
            started.elapsed().as_millis()
        );
    }
}
