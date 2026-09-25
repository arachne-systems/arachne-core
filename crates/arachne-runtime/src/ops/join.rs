//! Joiner side: begin a join from an invitation, fetch the invitation
//! checkpoint, ask a member for admission, stage the Welcome, and the
//! native join driver (`drive_join`). Also the member side of the
//! invitation checkpoint exchange (serving pages).

use arachne_api::{ApiError, EndpointId, ErrorCode};
use arachne_node::ControlClient;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::errors::{self, security};
use crate::membership::JoinStep;
use crate::ops::admission::{
    admission_history_page_packet, decode_admission_reply, admission_offer_candidate, admission_request_packet, live,
    live_mut, parse_admission_offer,
};
use crate::ops::candidate::{self, AdoptArgs, MemberView};
use crate::ops::{self, Op};
use crate::session::{activity_view, seal_state, transition_activity};
use crate::workspace_activity::ActivityView;
use crate::{Session, StagedWorkspace, WorkspacePhase, WorkspaceTransition, admission_state, persistence};

/// `DFIC\x02 | u32 offset | checkpoint request proof`; answered by one
/// `DFCP\x01` checkpoint page (B3a).
pub(crate) const INVITATION_CHECKPOINT_REQUEST: &[u8; 5] = b"DFIC\x02";
const INVITATION_CHECKPOINT_PAGE: &[u8; 5] = b"DFCP\x01";
pub(crate) const CHECKPOINT_PAGE_BYTES: usize = arachne_node::MAX_CONTROL_REPLY - 13;

/// Durable Iroh-only routing state for one pending admission. A selected peer
/// means the request may already have left this endpoint, so retries stay on
/// that authenticated Iroh identity until it yields a retained result.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct JoinLifecycle {
    pub(crate) peers: Vec<[u8; 32]>,
    pub(crate) selected: Option<[u8; 32]>,
    #[serde(default)]
    pub(crate) cursor: usize,
}

impl JoinLifecycle {
    pub(crate) fn new(peers: Vec<[u8; 32]>) -> Result<Self, ApiError> {
        if peers.is_empty()
            || peers.len() > 3
            || peers.iter().any(|peer| peer.iter().all(|byte| *byte == 0))
            || peers.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(ApiError::invalid_input(
                "peers",
                "join lifecycle requires one to three distinct Iroh peers",
            ));
        }
        Ok(Self {
            peers,
            selected: None,
            cursor: 0,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ApiError> {
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
            return Err(ApiError::storage_corrupt("invalid persisted join lifecycle"));
        }
        Ok(())
    }

    pub(crate) fn advance(&mut self) {
        self.selected = None;
        self.cursor = (self.cursor + 1) % self.peers.len();
    }
}

pub(crate) enum JoinAttemptOutcome {
    NotSent,
    Waiting,
    Reply {
        value: Value,
        history_prefix: Vec<Value>,
    },
    Failed(String),
}

pub(crate) struct PendingJoinExchange {
    pub(crate) peer: [u8; 32],
    pub(crate) task: tokio::task::JoinHandle<JoinAttemptOutcome>,
}
impl Drop for PendingJoinExchange {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) struct PendingCheckpointExchange {
    pub(crate) peer: [u8; 32],
    pub(crate) task: tokio::task::JoinHandle<Result<CheckpointFound, ApiError>>,
}
impl Drop for PendingCheckpointExchange {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ---------------------------------------------------------------------------
// Args and replies
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BeginJoinArgs {
    pub invitation: Vec<u8>,
    #[serde(default)]
    pub checkpoint: Vec<u8>,
    pub display_name: String,
    #[serde(default)]
    pub peers: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchCheckpointArgs {
    #[serde(default)]
    pub peer: Option<[u8; 32]>,
    #[serde(default)]
    pub peers: Vec<[u8; 32]>,
    pub invitation: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestAdmissionArgs {
    pub peer: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StageJoinArgs {
    pub commits: Vec<JoinStep>,
    #[serde(default)]
    pub welcome: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestorePendingJoinArgs {
    pub workspace: [u8; 32],
    #[serde(default)]
    pub snapshot: Vec<u8>,
}

/// A pending join: the joiner's identity and its admission request.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct PendingJoinInfo {
    pub workspace: [u8; 32],
    pub workspace_name: Option<String>,
    pub endpoint: [u8; 32],
    pub state: &'static str,
    pub durable: bool,
    pub member: MemberView,
    pub key_package: Vec<u8>,
    pub personal_invitation: bool,
    pub admission_request: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity: Option<ActivityView>,
}

/// A verified invitation checkpoint and the member that served it.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct CheckpointFound {
    pub workspace: [u8; 32],
    pub checkpoint: Vec<u8>,
    pub peer: [u8; 32],
}

/// Sealed state for a host that does not use native storage.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Sealed {
    pub workspace: [u8; 32],
    pub snapshot: Vec<u8>,
}

/// A join candidate that awaits the host's save.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct StagedJoin {
    pub workspace: [u8; 32],
    pub workspace_name: Option<String>,
    pub snapshot: Vec<u8>,
    pub state: &'static str,
    pub durable: bool,
    pub activity: ActivityView,
}

// ---------------------------------------------------------------------------
// Ops
// ---------------------------------------------------------------------------

pub(crate) fn begin(session: &mut Session, args: BeginJoinArgs) -> Result<PendingJoinInfo, ApiError> {
    if session.workspace.is_some() || session.join.pending.is_some() {
        return Err(ApiError::wrong_state("session already owns workspace state"));
    }
    let invitation = arachne_security::Invitation::from_bytes(&args.invitation)
        .map_err(security(ErrorCode::InvitationInvalid))?;
    let pending = if args.checkpoint.is_empty() {
        arachne_security::PendingJoin::from_compact_invitation(
            &invitation,
            &session.node,
            &args.display_name,
        )
    } else {
        arachne_security::PendingJoin::from_invitation(
            &invitation,
            &args.checkpoint,
            &session.node,
            &args.display_name,
        )
    }
    .map_err(security(ErrorCode::InvitationInvalid))?;
    transition_activity(session, WorkspacePhase::Joining, None)?;
    let mut value = pending_metadata(&pending, session.node.id())?;
    value.activity = Some(activity_view(session));
    session.join.pending = Some(pending);
    session.join.lifecycle = if args.peers.is_empty() {
        None
    } else {
        Some(JoinLifecycle::new(args.peers)?)
    };
    session.join.history_prefix.clear();
    Ok(value)
}

pub(crate) fn seal_pending(session: &mut Session) -> Result<Sealed, ApiError> {
    let pending = session
        .join
        .pending
        .as_ref()
        .ok_or_else(errors::no_pending_join)?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    Ok(Sealed {
        workspace: pending.workspace_id(),
        snapshot: pending
            .seal(key)
            .map_err(security(ErrorCode::StorageFailed))?,
    })
}

pub(crate) fn restore_pending(
    session: &mut Session,
    args: RestorePendingJoinArgs,
) -> Result<PendingJoinInfo, ApiError> {
    if session.workspace.is_some() || session.join.pending.is_some() {
        return Err(ApiError::wrong_state("session already owns workspace state"));
    }
    let key = session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    let pending = arachne_security::PendingJoin::restore(
        key,
        session.node.id(),
        args.workspace,
        &args.snapshot,
    )
    .map_err(security(ErrorCode::StorageCorrupt))?;
    let mut value = pending_metadata(&pending, session.node.id())?;
    transition_activity(session, WorkspacePhase::Joining, None)?;
    value.activity = Some(activity_view(session));
    session.join.pending = Some(pending);
    session.join.lifecycle = None;
    session.join.history_prefix.clear();
    Ok(value)
}

/// Find the current checkpoint of an invitation from one of up to three
/// members. The first verified checkpoint wins.
pub(crate) fn fetch_checkpoint(
    session: &mut Session,
    mut args: FetchCheckpointArgs,
) -> Result<CheckpointFound, ApiError> {
    if let Some(peer) = args.peer {
        args.peers.insert(0, peer);
    }
    session.runtime.block_on(request_invitation_checkpoint(
        session.node.control_client(),
        session.node.id(),
        args.invitation,
        args.peers,
    ))
}

/// Stage the Welcome and the history steps that lead to it. The prefix
/// this session fetched earlier is replayed first, never trusted.
pub(crate) fn stage(session: &mut Session, args: StageJoinArgs) -> Result<StagedJoin, ApiError> {
    let StageJoinArgs { commits, welcome } = args;
    if commits.is_empty() || commits.len() > arachne_security::HISTORY_CHUNK_STEPS {
        return Err(ApiError::invalid_input(
            "commits",
            "join history exceeds step bounds",
        ));
    }
    let pending = session
        .join
        .pending
        .as_ref()
        .ok_or_else(errors::no_pending_join)?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    let mut proof = pending
        .join_proof()
        .map_err(security(ErrorCode::InvitationInvalid))?;
    // Replay the rolled-over prefix from the pinned checkpoint before the
    // chunk the host carried back. Nothing is accepted on the strength of
    // having been fetched earlier: a truncated or tampered prefix fails
    // here exactly as it would on a first, unrolled verification.
    for value in &session.join.history_prefix {
        let step: JoinStep = serde_json::from_value(value.clone())
            .map_err(|error| ApiError::internal(error.to_string()))?;
        let (authorization, commit) = step.parts()?;
        proof
            .apply_transition(&authorization, &commit)
            .map_err(security(ErrorCode::InvalidInput))?;
    }
    for step in commits {
        let (authorization, commit) = step.parts()?;
        proof
            .apply_transition(&authorization, &commit)
            .map_err(security(ErrorCode::InvalidInput))?;
    }
    let workspace = pending
        .prepare_workspace(&proof, &welcome)
        .map_err(security(ErrorCode::InvalidInput))?;
    let snapshot = seal_state(session.records.is_some(), &workspace, key, None, None)?;
    let workspace_id = workspace.id();
    let workspace_name = workspace
        .workspace_name()
        .map_err(security(ErrorCode::Internal))?;
    session.transition.staged = Some(StagedWorkspace {
        publisher: None,
        inbox: None,
        transition: WorkspaceTransition::Join,
        workspace,
        snapshot: snapshot.clone(),
    });
    transition_activity(session, WorkspacePhase::Synchronizing, None)?;
    Ok(StagedJoin {
        workspace: workspace_id,
        workspace_name,
        snapshot,
        state: "awaiting_join_save",
        durable: false,
        activity: activity_view(session),
    })
}

/// Ask one member for admission and collect the retained reply, paging its
/// history. The reply is the member's JSON, passed on (typed in step 4).
pub(crate) fn request_admission(
    session: &mut Session,
    args: RequestAdmissionArgs,
) -> Result<Value, ApiError> {
    let peer = args.peer;
    let from_peer = |detail: &str| ApiError::transport_failed(Some(EndpointId::from_bytes(peer)), detail);
    let too_much = |detail: &str| ApiError::limit_reached("admission history", 0, detail);
    let pending = session
        .join
        .pending
        .as_ref()
        .ok_or_else(errors::no_pending_join)?;
    let request = pending
        .admission_request()
        .map_err(security(ErrorCode::WrongState))?;
    let name = pending.member().display_name().as_bytes();
    let packet = admission_request_packet(request, name)?;
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
        Err(error) => return Err(errors::node(error)),
    };
    // Every accepted page's wire size, so the caller can prove the
    // responder stayed inside the control-reply bound while rolling a long
    // history over many pages.
    let mut page_bytes = vec![reply.len()];
    let mut reply: Value =
        decode_admission_reply(&reply).map_err(|_| from_peer("invalid admission reply"))?;
    if reply
        .get("history_complete")
        .is_some_and(|complete| !complete.as_bool().unwrap_or(false))
    {
        let mut commits = reply["commits"]
            .as_array()
            .cloned()
            .ok_or_else(|| from_peer("admission history page missing commits"))?;
        let mut offset = reply["history_next"]
            .as_u64()
            .ok_or_else(|| from_peer("admission history page missing next offset"))?
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
                return Err(too_much("admission history page count exceeds bounds"));
            }
            let page = admission_history_page_packet(request, offset)?;
            let page = session
                .runtime
                .block_on(session.node.request_control(peer, &page))
                .map_err(errors::node)?;
            total_bytes = total_bytes.saturating_add(page.len());
            if total_bytes > arachne_security::MAX_JOIN_HISTORY_BYTES {
                return Err(too_much("admission history exceeds transport bounds"));
            }
            page_bytes.push(page.len());
            let page: Value = decode_admission_reply(&page)
                .map_err(|_| from_peer("invalid admission history page"))?;
            // A served page carries the retained reply plus its paging
            // markers; only a refusal carries a `state`. Requiring both was
            // unreachable, and no branch short enough to fit one page ever
            // reached this loop to show it.
            if page.get("history_page").and_then(Value::as_bool) != Some(true) {
                return Err(from_peer("admission history page was not accepted"));
            }
            if page["history_offset"].as_u64() != Some(offset as u64) {
                return Err(from_peer("admission history page offset mismatch"));
            }
            let page_commits = page["commits"]
                .as_array()
                .ok_or_else(|| from_peer("admission history page missing commits"))?;
            let next = page["history_next"]
                .as_u64()
                .ok_or_else(|| from_peer("admission history page missing next offset"))?
                as usize;
            // A page carries steps, except the final page that carries only
            // the Welcome.
            let complete = page["history_complete"].as_bool() == Some(true);
            if (page_commits.is_empty() && !complete) || next < offset || (next == offset && !complete) {
                return Err(from_peer("admission history page made no progress"));
            }
            if commits.len() + page_commits.len() > arachne_security::MAX_JOIN_HISTORY_STEPS {
                return Err(too_much("admission history exceeds step bounds"));
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
        session.join.history_prefix = prefix;
    } else {
        session.join.history_prefix.clear();
    }
    if reply.get("commits").is_some() {
        // Only a reply that actually served history reports page sizes; a
        // queued or refused attempt keeps its exact previous shape.
        reply["history_page_bytes"] = json!(page_bytes);
    }
    Ok(reply)
}

fn no_lifecycle() -> ApiError {
    ApiError::wrong_state("join lifecycle has no persisted Iroh peers")
}

fn commit_pending_join(session: &mut Session) -> Result<(), ApiError> {
    persistence::commit_pending_join(session)
}

/// Stage the join through its own op's guards, as a drive op's inner step.
fn nested_stage(session: &mut Session, commits: Vec<JoinStep>, welcome: Vec<u8>) -> Result<StagedJoin, ApiError> {
    let session = live_mut(session)?;
    ops::nested(session, Op::StageJoin, |session| {
        stage(session, StageJoinArgs { commits, welcome })
    })
}

/// Advance a join restored from native record storage: take a pushed
/// admission result, fetch the checkpoint of a compact invitation, or ask
/// the next member. The reply is an open event (typed in ADR step 4).
pub(crate) fn drive(session: &mut Session) -> Result<Value, ApiError> {
    if live(session)?.records.is_none() {
        return Err(ApiError::wrong_state(
            "join lifecycle requires native record storage",
        ));
    }
    if let Some(incoming) = live_mut(session)?
        .node
        .poll_control_matching(admission_offer_candidate)
    {
        let peer = incoming.peer();
        let allowed = live(session)?
            .join
            .lifecycle
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
        if let Some(exchange) = live_mut(session)?.join.exchange.take() {
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
        let staged = match nested_stage(session, commits, welcome) {
            Ok(staged) => staged,
            Err(_) => {
                let _ = incoming.respond(vec![0]);
                return Ok(json!({"state":admission_state::UNAVAILABLE,
                    "reason":"invalid_admission_offer","peer":peer}));
            }
        };
        live_mut(session)?.transition.inbound = Some(incoming);
        return serde_json::to_value(staged).map_err(errors::encode);
    }
    let compact_pending = live(session)?
        .join
        .pending
        .as_ref()
        .is_some_and(|pending| pending.admission_request().is_err());
    if compact_pending {
        if let Some(mut exchange) = live_mut(session)?.join.checkpoint_exchange.take() {
            if !exchange.task.is_finished() {
                let peer = exchange.peer;
                live_mut(session)?.join.checkpoint_exchange = Some(exchange);
                return Ok(json!({"state":"admission_pending", "phase":"checkpoint", "peer":peer}));
            }
            match live(session)?
                .runtime
                .block_on(&mut exchange.task)
                .map_err(errors::task("checkpoint exchange task cancelled"))?
            {
                Ok(found) => {
                    let session = live_mut(session)?;
                    session
                        .join
                        .pending
                        .as_mut()
                        .ok_or_else(errors::no_pending_join)?
                        .complete_checkpoint(&found.checkpoint)
                        .map_err(security(ErrorCode::InvitationInvalid))?;
                    let lifecycle = session.join.lifecycle.as_mut().ok_or_else(no_lifecycle)?;
                    lifecycle.selected = Some(found.peer);
                    lifecycle.cursor = lifecycle
                        .peers
                        .iter()
                        .position(|candidate| *candidate == found.peer)
                        .unwrap_or(lifecycle.cursor);
                    commit_pending_join(session)?;
                }
                Err(reason) => {
                    let session = live_mut(session)?;
                    let lifecycle = session.join.lifecycle.as_mut().ok_or_else(no_lifecycle)?;
                    if lifecycle.selected == Some(exchange.peer) {
                        lifecycle.advance();
                        commit_pending_join(session)?;
                    }
                    let reason = errors::legacy_text(&reason);
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
                let session = live_mut(session)?;
                let lifecycle = session.join.lifecycle.as_ref().ok_or_else(no_lifecycle)?;
                let mut peers = Vec::with_capacity(lifecycle.peers.len());
                if let Some(selected) = lifecycle.selected {
                    peers.push(selected);
                }
                for peer in lifecycle.peers.iter().skip(lifecycle.cursor) {
                    if !peers.contains(peer) {
                        peers.push(*peer);
                    }
                }
                let selected = *peers
                    .first()
                    .ok_or_else(|| ApiError::peer_unreachable(None, "no reachable workspace member"))?;
                let invitation = session
                    .join
                    .pending
                    .as_ref()
                    .ok_or_else(errors::no_pending_join)?
                    .deferred_invitation()
                    .map_err(security(ErrorCode::WrongState))?
                    .to_vec();
                (peers, invitation, selected)
            };
            {
                let session = live_mut(session)?;
                let lifecycle = session.join.lifecycle.as_mut().ok_or_else(no_lifecycle)?;
                lifecycle.selected = Some(selected);
                commit_pending_join(session)?;
            }
            let wake = live(session)?.node.control_signal();
            let client = live(session)?.node.control_client();
            let requester = live(session)?.node.id();
            let task = live(session)?.runtime.spawn(async move {
                let outcome =
                    request_invitation_checkpoint(client, requester, invitation, peers).await;
                wake.notify_one();
                outcome
            });
            live_mut(session)?.join.checkpoint_exchange = Some(PendingCheckpointExchange {
                peer: selected,
                task,
            });
            return Ok(json!({"state":"admission_pending", "phase":"checkpoint", "peer":selected}));
        }
    }
    let mut reply = None;
    if let Some(mut exchange) = live_mut(session)?.join.exchange.take() {
        if !exchange.task.is_finished() {
            let peer = exchange.peer;
            live_mut(session)?.join.exchange = Some(exchange);
            return Ok(json!({"state":"admission_pending", "peer":peer}));
        }
        let outcome = live(session)?
            .runtime
            .block_on(&mut exchange.task)
            .map_err(errors::task("join exchange task cancelled"))?;
        match outcome {
            JoinAttemptOutcome::NotSent => {
                let session = live_mut(session)?;
                let lifecycle = session.join.lifecycle.as_mut().ok_or_else(no_lifecycle)?;
                if lifecycle.selected == Some(exchange.peer) {
                    lifecycle.advance();
                    commit_pending_join(session)?;
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
                let session = live_mut(session)?;
                session.join.history_prefix = history_prefix;
                reply = Some(value);
            }
        }
    }
    if let Some(reply) = reply {
        if reply.get("state").is_some() {
            // Only administrators admit: a member that is not one cannot
            // help this join, so ask the next member.
            if reply["reason"] == admission_state::ADMINISTRATOR_REQUIRED {
                let session = live_mut(session)?;
                let lifecycle = session.join.lifecycle.as_mut().ok_or_else(no_lifecycle)?;
                lifecycle.advance();
                commit_pending_join(session)?;
            }
            return Ok(reply);
        }
        let bad_reply = |detail: &str| ApiError::transport_failed(None, detail);
        let commits = if let Some(commits) = reply.get("commits") {
            serde_json::from_value(commits.clone())
                .map_err(|_| bad_reply("admission reply commits are invalid"))?
        } else {
            serde_json::from_value(json!([{
                "commit": reply["commit"].clone(),
                "authorization": reply["authorization"].clone(),
            }]))
            .map_err(|_| bad_reply("admission reply is incomplete"))?
        };
        let welcome = serde_json::from_value(reply["welcome"].clone())
            .map_err(|_| bad_reply("admission reply has no Welcome"))?;
        let staged = nested_stage(session, commits, welcome)?;
        let snapshot = staged.snapshot;
        persistence::commit_candidate(live_mut(session)?, &snapshot)?;
        let joined = {
            let session = live_mut(session)?;
            ops::nested(session, Op::AdoptJoin, |session| {
                candidate::adopt_join(session, AdoptArgs { snapshot })
            })?
        };
        let mut joined = serde_json::to_value(joined).map_err(errors::encode)?;
        joined["state"] = json!("workspace_joined");
        return Ok(joined);
    }

    let (peer, request, name) = {
        let session = live_mut(session)?;
        let lifecycle = session.join.lifecycle.as_mut().ok_or_else(no_lifecycle)?;
        let peer = lifecycle
            .selected
            .or_else(|| lifecycle.peers.get(lifecycle.cursor).copied());
        let Some(peer) = peer else {
            return Ok(json!({"state":admission_state::UNAVAILABLE,
                "reason":"no_reachable_member"}));
        };
        if lifecycle.selected.is_none() {
            lifecycle.selected = Some(peer);
            commit_pending_join(session)?;
        }
        let pending = session
            .join
            .pending
            .as_ref()
            .ok_or_else(errors::no_pending_join)?;
        (
            peer,
            pending
                .admission_request()
                .map_err(security(ErrorCode::WrongState))?
                .to_vec(),
            pending.member().display_name().as_bytes().to_vec(),
        )
    };
    let wake = live(session)?.node.control_signal();
    let client = live(session)?.node.control_client();
    let task = live(session)?.runtime.spawn(async move {
        let outcome = request_join_exchange(client, peer, request, name).await;
        wake.notify_one();
        outcome
    });
    live_mut(session)?.join.exchange = Some(PendingJoinExchange { peer, task });
    Ok(json!({"state":"admission_pending", "peer":peer}))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn pending_metadata(
    pending: &arachne_security::PendingJoin,
    endpoint: [u8; 32],
) -> Result<PendingJoinInfo, ApiError> {
    let internal = security(ErrorCode::Internal);
    Ok(PendingJoinInfo {
        workspace: pending.workspace_id(),
        workspace_name: pending.workspace_name().map_err(&internal)?,
        endpoint,
        state: "pending",
        durable: false,
        member: MemberView {
            id: pending.member().id(),
            display_name: pending.member().display_name().to_owned(),
        },
        key_package: pending.key_package().map_err(&internal)?,
        personal_invitation: if pending.admission_request().is_ok() {
            pending.personal_invitation().map_err(&internal)?
        } else {
            false
        },
        admission_request: pending.admission_request().ok().map(<[u8]>::to_vec),
        activity: None,
    })
}

/// Pull one invitation checkpoint from up to three members.
async fn request_invitation_checkpoint(
    client: ControlClient,
    requester: [u8; 32],
    invitation: Vec<u8>,
    peers: Vec<[u8; 32]>,
) -> Result<CheckpointFound, ApiError> {
    let invitation = arachne_security::Invitation::from_bytes(&invitation)
        .map_err(security(ErrorCode::InvitationInvalid))?;
    if peers.is_empty()
        || peers.len() > 3
        || peers.iter().any(|peer| peer == &requester)
        || peers
            .iter()
            .enumerate()
            .any(|(index, peer)| peers[..index].contains(peer))
    {
        return Err(ApiError::invalid_input(
            "peers",
            "checkpoint discovery requires one to three distinct peers",
        ));
    }
    let mut last_error = None;
    for peer in peers {
        let proof = invitation
            .checkpoint_request(requester, peer)
            .map_err(security(ErrorCode::InvitationInvalid))?;
        let checkpoint = match fetch_invitation_checkpoint(&client, peer, &proof).await {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match invitation.join_proof(&checkpoint) {
            Ok(_) => {
                return Ok(CheckpointFound {
                    workspace: invitation.workspace_id(),
                    checkpoint,
                    peer,
                });
            }
            Err(error) => last_error = Some(security(ErrorCode::InvitationInvalid)(error)),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        ApiError::peer_unreachable(None, "no authorized workspace member is reachable")
    }))
}

/// Pull one invitation checkpoint in pages. A checkpoint is up to
/// `MAX_CHECKPOINT` (about 832 KiB), larger than one control reply. Pages are
/// full except the last, so a peer cannot stretch the exchange: the page count
/// is exactly `total.div_ceil(CHECKPOINT_PAGE_BYTES)`, at most 7.
async fn fetch_invitation_checkpoint(
    client: &ControlClient,
    peer: [u8; 32],
    proof: &[u8],
) -> Result<Vec<u8>, ApiError> {
    let mut checkpoint = Vec::new();
    let mut total = None;
    loop {
        let offset = u32::try_from(checkpoint.len())
            .map_err(|_| ApiError::internal("checkpoint too large"))?;
        let mut packet = INVITATION_CHECKPOINT_REQUEST.to_vec();
        packet.extend(offset.to_be_bytes());
        packet.extend(proof);
        let page = client
            .clone()
            .request_control(peer, &packet)
            .await
            .map_err(errors::node)?;
        let (page_total, page_offset, chunk) = parse_checkpoint_page(&page)?;
        if page_offset != checkpoint.len() || total.is_some_and(|total| total != page_total) {
            return Err(ApiError::transport_failed(
                Some(EndpointId::from_bytes(peer)),
                "invitation checkpoint page mismatch",
            ));
        }
        total = Some(page_total);
        checkpoint.extend(chunk);
        if checkpoint.len() == page_total {
            return Ok(checkpoint);
        }
    }
}

/// `DFCP\x01 | u32 total | u32 offset | chunk`; the chunk is exactly
/// `min(CHECKPOINT_PAGE_BYTES, total - offset)` bytes.
fn parse_checkpoint_page(page: &[u8]) -> Result<(usize, usize, &[u8]), ApiError> {
    let bad = |detail: &str| ApiError::transport_failed(None, detail);
    if page.len() < 13 || !page.starts_with(INVITATION_CHECKPOINT_PAGE) {
        return Err(bad("invalid invitation checkpoint page"));
    }
    let total = u32::from_be_bytes(page[5..9].try_into().unwrap()) as usize;
    let offset = u32::from_be_bytes(page[9..13].try_into().unwrap()) as usize;
    let chunk = &page[13..];
    if total == 0
        || total > arachne_security::MAX_CHECKPOINT
        || offset >= total
        || chunk.len() != CHECKPOINT_PAGE_BYTES.min(total - offset)
    {
        return Err(bad("invalid invitation checkpoint page bounds"));
    }
    Ok((total, offset, chunk))
}

/// Serve one page of the checkpoint an invitation holder may fetch.
pub(crate) fn invitation_checkpoint_page(
    workspace: &arachne_security::Workspace,
    requester: [u8; 32],
    responder: [u8; 32],
    request: &[u8],
) -> Result<Vec<u8>, ApiError> {
    let body = request
        .strip_prefix(INVITATION_CHECKPOINT_REQUEST)
        .filter(|body| body.len() > 4)
        .ok_or_else(|| ApiError::invalid_input("request", "invalid invitation checkpoint request"))?;
    let offset = u32::from_be_bytes(body[..4].try_into().unwrap()) as usize;
    let checkpoint = workspace
        .checkpoint_for_invitation(requester, responder, &body[4..])
        .map_err(security(ErrorCode::NotAuthorized))?;
    if offset >= checkpoint.len() {
        return Err(ApiError::invalid_input(
            "offset",
            "invitation checkpoint page offset is out of bounds",
        ));
    }
    let end = checkpoint.len().min(offset + CHECKPOINT_PAGE_BYTES);
    let too_large = || ApiError::internal("checkpoint too large");
    let mut page = INVITATION_CHECKPOINT_PAGE.to_vec();
    page.extend(
        u32::try_from(checkpoint.len())
            .map_err(|_| too_large())?
            .to_be_bytes(),
    );
    page.extend(u32::try_from(offset).map_err(|_| too_large())?.to_be_bytes());
    page.extend(&checkpoint[offset..end]);
    Ok(page)
}

pub(crate) fn invitation_checkpoint_reply(
    session: &Session,
    requester: [u8; 32],
    request: &[u8],
) -> Result<Vec<u8>, ApiError> {
    let workspace = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    invitation_checkpoint_page(workspace, requester, session.node.id(), request)
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

async fn request_join_exchange(
    client: ControlClient,
    peer: [u8; 32],
    request: Vec<u8>,
    name: Vec<u8>,
) -> JoinAttemptOutcome {
    let packet = match admission_request_packet(&request, &name) {
        Ok(packet) => packet,
        Err(error) => return JoinAttemptOutcome::Failed(errors::text(error)),
    };

    let first = match client.clone().request_control(peer, &packet).await {
        Ok(reply) => reply,
        Err(error) => return join_attempt_error(error, true),
    };
    let mut page_bytes = vec![first.len()];
    let mut reply: Value = match decode_admission_reply(&first) {
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
            let page = match admission_history_page_packet(&request, offset) {
                Ok(packet) => packet,
                Err(error) => return JoinAttemptOutcome::Failed(errors::text(error)),
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
            let page: Value = match decode_admission_reply(&page) {
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
            // A page carries steps, except the final page that carries only
            // the Welcome.
            let complete = page["history_complete"].as_bool() == Some(true);
            if (page_commits.is_empty() && !complete) || next < offset || (next == offset && !complete) {
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
    fn checkpoint_pages_are_full_and_bounded() {
        let page = |total: u32, offset: u32, chunk: usize| {
            [
                INVITATION_CHECKPOINT_PAGE.as_slice(),
                &total.to_be_bytes(),
                &offset.to_be_bytes(),
                &vec![1; chunk],
            ]
            .concat()
        };
        let total = CHECKPOINT_PAGE_BYTES as u32 + 5;
        assert!(parse_checkpoint_page(&page(total, 0, CHECKPOINT_PAGE_BYTES)).is_ok());
        assert!(parse_checkpoint_page(&page(total, CHECKPOINT_PAGE_BYTES as u32, 5)).is_ok());
        // A short page would let a peer stretch the exchange.
        assert!(parse_checkpoint_page(&page(total, 0, 1)).is_err());
        assert!(parse_checkpoint_page(&page(total, total, 0)).is_err());
        let over = arachne_security::MAX_CHECKPOINT as u32 + 1;
        assert!(parse_checkpoint_page(&page(over, 0, CHECKPOINT_PAGE_BYTES)).is_err());
        assert!(CHECKPOINT_PAGE_BYTES + 13 <= arachne_node::MAX_CONTROL_REPLY);
    }

    #[test]
    fn a_lifecycle_needs_one_to_three_distinct_peers() {
        for peers in [vec![], vec![[1; 32]; 2], vec![[0; 32]], vec![[1; 32], [2; 32], [3; 32], [4; 32]]] {
            let error = JoinLifecycle::new(peers).err().unwrap();
            assert_eq!(error.code(), ErrorCode::InvalidInput);
        }
    }
}
