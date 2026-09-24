//! Recovery, direct recovery and current view: the host ops that find a
//! holder, verify its answer and stage the recovered objects, and the serving
//! side that answers peers' queries from committed state.

use std::collections::BTreeSet;

use arachne_api::{ApiError, EndpointId, ErrorCode};
use arachne_node::Topic;
use arachne_routing::PublicationContext;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::errors::{self, delivery, security};
use crate::ops::publication::{missed_since_commit, publisher_or_new};
use crate::session::seal_state;
use crate::{
    MAX_WORKSPACE_OVERLAY_PATHS, PendingControl, Session, StagedWorkspace, WorkspaceTransition,
};

// ---------------------------------------------------------------------------
// State held by `Session::recovery`
// ---------------------------------------------------------------------------

pub(crate) struct ReadyRange {
    pub(crate) query: arachne_delivery::RangeQuery,
    pub(crate) peer: [u8; 32],
    pub(crate) reply: Vec<u8>,
    pub(crate) packet_count: usize,
    pub(crate) automatic: bool,
}

pub(crate) struct ReadyDirectRange {
    pub(crate) query: arachne_delivery::wire::DirectRangeQuery,
    pub(crate) peer: [u8; 32],
    pub(crate) reply: Vec<u8>,
    pub(crate) packet_count: usize,
}

pub(crate) struct ReadyCurrentView {
    pub(crate) query: arachne_delivery::current::CurrentViewQuery,
    pub(crate) peer: [u8; 32],
    pub(crate) reply: Vec<u8>,
    pub(crate) cut: u64,
    pub(crate) value_count: usize,
}

/// One holder's answer: its endpoint and the reply bytes or the failure.
pub(crate) type RecoveryReply = ([u8; 32], Result<Vec<u8>, ApiError>);

pub(crate) struct PendingRange {
    pub(crate) query: arachne_delivery::RangeQuery,
    pub(crate) available: Option<arachne_delivery::wire::AvailableRangeQuery>,
    pub(crate) automatic: bool,
    pub(crate) replies: mpsc::Receiver<RecoveryReply>,
    pub(crate) task: tokio::task::JoinHandle<()>,
    pub(crate) attempted: usize,
    pub(crate) reason: Option<String>,
}
impl Drop for PendingRange {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) struct PendingDirectRange {
    pub(crate) query: arachne_delivery::wire::DirectRangeQuery,
    pub(crate) replies: mpsc::Receiver<RecoveryReply>,
    pub(crate) task: tokio::task::JoinHandle<()>,
    pub(crate) attempted: usize,
    pub(crate) reason: Option<String>,
}
impl Drop for PendingDirectRange {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) struct PendingCurrentView {
    pub(crate) query: arachne_delivery::current::CurrentViewQuery,
    pub(crate) automatic: bool,
    pub(crate) replies: mpsc::Receiver<RecoveryReply>,
    pub(crate) task: tokio::task::JoinHandle<()>,
    pub(crate) attempted: usize,
    pub(crate) reason: Option<String>,
    pub(crate) best: Option<ReadyCurrentView>,
}
impl Drop for PendingCurrentView {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchRangeArgs {
    #[serde(default)]
    pub peer: Option<[u8; 32]>,
    #[serde(default)]
    pub author: Option<[u8; 32]>,
    pub revision: u64,
    pub topics: Vec<String>,
    #[serde(default)]
    pub after: Option<u64>,
    #[serde(default)]
    pub through: Option<u64>,
    /// The author epoch to recover (A3f): any epoch in the receive window.
    /// Absent: the current epoch.
    #[serde(default)]
    pub epoch: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StageRangeArgs {
    /// Unix seconds (UTC) by this node's clock; 0 keeps no copy for
    /// third-party recovery.
    #[serde(default)]
    pub retain_until: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchDirectArgs {
    pub author: [u8; 32],
    pub revision: u64,
    pub topic: String,
    pub recipients: Vec<[u8; 32]>,
    pub after: u64,
    pub through: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchCurrentViewArgs {
    #[serde(default)]
    pub peer: Option<[u8; 32]>,
    pub authority: [u8; 32],
    pub revision: u64,
    pub topic: String,
    pub selector: [u8; 32],
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CutoffArgs {
    pub peer: [u8; 32],
    pub revision: u64,
    pub topics: Vec<String>,
    /// The epoch whose retained window to ask for (A3f): any epoch in the
    /// receive window. Absent: the current epoch.
    #[serde(default)]
    pub epoch: Option<u64>,
}

// ---------------------------------------------------------------------------
// Replies. Each carries `accepted_progress: false`: no recovery step claims
// progress before its candidate is adopted.
// ---------------------------------------------------------------------------

/// Where a recovery range stands.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum RangeStatus {
    RecoverySourceWaiting {
        accepted_progress: bool,
    },
    RecoveryRangePending {
        candidate_count: usize,
        automatic_source: bool,
        accepted_progress: bool,
    },
    RecoveryRangeCancelled {
        accepted_progress: bool,
    },
    RecoverySourceUnavailable {
        attempted: usize,
        reason: String,
        automatic_source: bool,
        accepted_progress: bool,
    },
    RecoveryRangeRejected {
        reason: String,
        accepted_progress: bool,
    },
    RecoveryRangeReady(RangeReady),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RangeReady {
    pub workspace: [u8; 32],
    pub author: [u8; 32],
    pub peer: [u8; 32],
    pub epoch: u64,
    pub revision: u64,
    pub after: u64,
    pub through: u64,
    pub packet_count: usize,
    pub retained_bytes: usize,
    pub automatic_source: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempted: Option<usize>,
    pub accepted_progress: bool,
}

/// A direct stream with a gap before its next object.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct DirectGap {
    pub state: &'static str,
    pub author: [u8; 32],
    pub revision: u64,
    pub topic: String,
    pub recipients: Vec<[u8; 32]>,
    pub after: u64,
    pub through: u64,
}

/// Where a direct recovery stands.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum DirectStatus {
    DirectRecoverySourceWaiting {
        accepted_progress: bool,
    },
    DirectRecoveryPending {
        candidate_count: usize,
        accepted_progress: bool,
    },
    DirectRecoveryCancelled {
        accepted_progress: bool,
    },
    DirectRecoverySourceUnavailable {
        attempted: usize,
        reason: String,
        accepted_progress: bool,
    },
    DirectRecoveryReady {
        workspace: [u8; 32],
        author: [u8; 32],
        peer: [u8; 32],
        epoch: u64,
        revision: u64,
        topic: String,
        after: u64,
        through: u64,
        packet_count: usize,
        retained_bytes: usize,
        attempted: usize,
        accepted_progress: bool,
    },
}

/// Where a current-view fetch stands.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum CurrentViewStatus {
    CurrentViewSourceWaiting {
        accepted_progress: bool,
    },
    CurrentViewPending {
        candidate_count: usize,
        automatic_source: bool,
        accepted_progress: bool,
    },
    CurrentViewCancelled {
        accepted_progress: bool,
    },
    CurrentViewReady {
        cut: u64,
        value_count: usize,
        automatic_source: bool,
        attempted: usize,
        accepted_progress: bool,
    },
    CurrentViewUnavailable {
        #[serde(skip_serializing_if = "Option::is_none")]
        attempted: Option<usize>,
        reason: String,
        automatic_source: bool,
        accepted_progress: bool,
    },
}

/// Where a recovery cutoff discovery stands.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum CutoffStatus {
    RecoveryCutoffPending {
        accepted_progress: bool,
    },
    RecoveryCutoffObserved {
        workspace: [u8; 32],
        author: [u8; 32],
        peer: [u8; 32],
        epoch: u64,
        revision: u64,
        topics: Vec<String>,
        head: u64,
        retained_after: u64,
        accepted_through: u64,
        accepted_progress: bool,
    },
    RecoveryCutoffDenied {
        accepted_progress: bool,
    },
}

/// A recovery candidate that awaits the host's save.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct StagedRecovery {
    pub workspace: [u8; 32],
    pub snapshot: Vec<u8>,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_through: Option<u64>,
    #[serde(flatten)]
    pub current_view: Option<crate::ops::candidate::CurrentViewCounts>,
    pub durable: bool,
    pub accepted_progress: bool,
}

/// The outcome of a stage op: a candidate, or a state with nothing staged.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum RecoveryStaged {
    Candidate(StagedRecovery),
    Nothing(NothingStaged),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NothingStaged {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_through: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_progress: Option<bool>,
}

// ---------------------------------------------------------------------------
// Shared checks
// ---------------------------------------------------------------------------

fn busy(session: &Session) -> bool {
    let recovery = &session.recovery;
    recovery.cutoff.is_some()
        || recovery.range.is_some()
        || recovery.ready_range.is_some()
        || recovery.direct_range.is_some()
        || recovery.ready_direct_range.is_some()
        || recovery.current_view.is_some()
        || recovery.ready_current_view.is_some()
}

fn from_peer(peer: [u8; 32], detail: &str) -> ApiError {
    ApiError::transport_failed(Some(EndpointId::from_bytes(peer)), detail)
}

/// Ask each candidate holder at once; answers arrive on the channel.
fn ask_holders(
    session: &Session,
    candidates: &[[u8; 32]],
    wire: &[u8],
) -> (usize, mpsc::Receiver<RecoveryReply>, tokio::task::JoinHandle<()>) {
    let requests = candidates
        .iter()
        .map(|peer| (*peer, session.node.request_control(*peer, wire)))
        .collect::<Vec<_>>();
    let candidate_count = requests.len();
    let (reply_tx, replies) = mpsc::channel(candidate_count);
    let task = session.runtime.spawn(async move {
        let mut pending = tokio::task::JoinSet::new();
        for (peer, request) in requests {
            pending.spawn(async move { (peer, request.await.map_err(errors::node)) });
        }
        while let Some(result) = pending.join_next().await {
            if let Ok(reply) = result
                && reply_tx.send(reply).await.is_err()
            {
                break;
            }
        }
    });
    (candidate_count, replies, task)
}

/// Re-check that `peer` may serve `author`'s `topics` under the current
/// scope and policy, before a result is shown or staged.
pub(crate) fn check_recovery_policy(
    session: &Session,
    peer: [u8; 32],
    author: [u8; 32],
    workspace: [u8; 32],
    epoch: u64,
    revision: u64,
    topics: &BTreeSet<Topic>,
) -> Result<(), ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    // A3f: any epoch still in the receive window may be recovered. An epoch
    // change also cancels pending recovery (`check_epoch_transition`).
    if owner.id() != workspace || !owner.in_receive_window(epoch) {
        return Err(ApiError::epoch_mismatch("recovery scope changed"));
    }
    if !owner
        .member_endpoints()
        .map_err(security(ErrorCode::Internal))?
        .contains(&peer)
    {
        return Err(ApiError::not_member("recovery peer is not a current member"));
    }
    let author_endpoint = owner
        .endpoints_for_members(&[author])
        .map_err(security(ErrorCode::NotMember))?[0];
    session
        .runtime
        .block_on(session.node.with_routing_policy(|policy| {
            // This re-checks a result held locally before it is shown. The
            // one-revision window is for peers' frames in flight; this device
            // knows it installed a newer policy, so the caller asks again.
            if policy
                .installed_revision(owner.id())
                .is_some_and(|installed| installed != revision)
            {
                return Err(ApiError::policy_mismatch("recovery scope changed"));
            }
            for topic in topics {
                let publishers = policy
                    .publishers(owner.id(), revision, session.node.id(), topic)
                    .map_err(errors::routing)?;
                if !publishers.contains(&author_endpoint) {
                    return Err(ApiError::not_authorized(
                        "recovery publisher is not authorized",
                    ));
                }
                if peer != author_endpoint
                    && !policy
                        .publishers(owner.id(), revision, peer, topic)
                        .map_err(errors::routing)?
                        .contains(&author_endpoint)
                {
                    return Err(ApiError::not_authorized(
                        "recovery holder is not authorized",
                    ));
                }
            }
            Ok(())
        }))
}

/// The epoch a recovery op asks for: the requested one if it is in the
/// receive window (A3f), else the current epoch.
fn recovery_epoch(owner: &arachne_security::Workspace, epoch: Option<u64>) -> Result<u64, ApiError> {
    match epoch {
        None => Ok(owner.epoch()),
        Some(epoch) if owner.in_receive_window(epoch) => Ok(epoch),
        Some(_) => Err(ApiError::epoch_mismatch(
            "recovery epoch is outside the receive window",
        )),
    }
}

fn topic_set(topics: Vec<String>) -> Result<BTreeSet<Topic>, ApiError> {
    let count = topics.len();
    let topics = topics
        .into_iter()
        .map(Topic::new)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(errors::routing)?;
    if topics.len() != count {
        return Err(ApiError::invalid_input("topics", "duplicate recovery topic"));
    }
    Ok(topics)
}

// ---------------------------------------------------------------------------
// Author ranges
// ---------------------------------------------------------------------------

/// Ask for an author's range: from `peer`, or automatically from live
/// neighbors and the author, continuing accepted progress.
pub(crate) fn fetch_range(session: &mut Session, args: FetchRangeArgs) -> Result<RangeStatus, ApiError> {
    let FetchRangeArgs {
        peer,
        author,
        revision,
        topics,
        after,
        through,
        epoch,
    } = args;
    if busy(session) {
        return Err(ApiError::wrong_state("recovery operation already pending"));
    }
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    if peer == Some(session.node.id())
        || topics.is_empty()
        || topics.len() > arachne_delivery::MAX_TOPICS
        || matches!((after, through), (Some(after), Some(through)) if after >= through)
        || matches!((after, through), (Some(_), None) | (None, Some(_)))
    {
        return Err(ApiError::invalid_input(
            "range",
            "invalid recovery peer, selection or range",
        ));
    }
    let topics = topic_set(topics)?;
    let epoch = recovery_epoch(owner, epoch)?;
    let author = match (author, peer) {
        (Some(author), _) => owner
            .endpoints_for_members(&[author])
            .map(|_| author)
            .map_err(security(ErrorCode::NotMember)),
        (None, Some(peer)) => owner
            .member_id_for_endpoint(peer)
            .map_err(security(ErrorCode::NotMember)),
        (None, None) => Err(ApiError::invalid_input(
            "author",
            "automatic recovery requires an original author",
        )),
    }?;
    let after = match after {
        Some(after) => after,
        None => session
            .delivery
            .inbox
            .as_ref()
            .ok_or_else(|| ApiError::wrong_state("automatic recovery requires object delivery"))?
            .recovery_progress(author, epoch, &topics),
    };
    let available = through
        .is_none()
        .then(|| arachne_delivery::wire::AvailableRangeQuery {
            workspace: owner.id(),
            author,
            epoch,
            policy_revision: revision,
            after,
            topics: topics.clone(),
        });
    let query = arachne_delivery::RangeQuery {
        workspace: owner.id(),
        author,
        epoch,
        policy_revision: revision,
        after,
        through: through.unwrap_or_else(|| after.saturating_add(1)),
        topics,
    };
    if query.after == query.through {
        return Err(ApiError::invalid_input("after", "recovery cursor exhausted"));
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
            .map_err(security(ErrorCode::NotMember))?[0];
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
        return Ok(RangeStatus::RecoverySourceWaiting {
            accepted_progress: false,
        });
    }
    let wire = match &available {
        Some(request) => request.to_wire(),
        None => query.to_wire(),
    }
    .map_err(delivery(ErrorCode::InvalidInput))?;
    let (candidate_count, replies, task) = ask_holders(session, &candidates, &wire);
    session.recovery.range = Some(PendingRange {
        query,
        available,
        automatic,
        replies,
        task,
        attempted: 0,
        reason: None,
    });
    Ok(RangeStatus::RecoveryRangePending {
        candidate_count,
        automatic_source: automatic,
        accepted_progress: false,
    })
}

pub(crate) fn cancel_range(session: &mut Session) -> Result<RangeStatus, ApiError> {
    drop(session.recovery.range.take());
    session.recovery.ready_range = None;
    Ok(RangeStatus::RecoveryRangeCancelled {
        accepted_progress: false,
    })
}

fn range_ready(ready: &ReadyRange, attempted: Option<usize>) -> RangeStatus {
    RangeStatus::RecoveryRangeReady(RangeReady {
        workspace: ready.query.workspace,
        author: ready.query.author,
        peer: ready.peer,
        epoch: ready.query.epoch,
        revision: ready.query.policy_revision,
        after: ready.query.after,
        through: ready.query.through,
        packet_count: ready.packet_count,
        retained_bytes: ready.reply.len(),
        automatic_source: ready.automatic,
        attempted,
        accepted_progress: false,
    })
}

/// One holder's answer, if any arrived. `None`: still waiting.
pub(crate) fn poll_range(session: &mut Session) -> Result<Option<RangeStatus>, ApiError> {
    let Some(active) = session.recovery.range.as_mut() else {
        return Ok(None);
    };
    let (peer, reply) = match active.replies.try_recv() {
        Ok(reply) => reply,
        Err(mpsc::error::TryRecvError::Empty) if !active.task.is_finished() => {
            return Ok(None);
        }
        Err(_) => {
            let mut pending = session.recovery.range.take().unwrap();
            if pending.automatic {
                return Ok(Some(RangeStatus::RecoverySourceUnavailable {
                    attempted: pending.attempted,
                    reason: pending.reason.take().unwrap_or_else(|| {
                        "no current holder supplied authenticated coverage".into()
                    }),
                    automatic_source: true,
                    accepted_progress: false,
                }));
            }
            return Err(ApiError::transport_failed(
                None,
                pending
                    .reason
                    .take()
                    .unwrap_or_else(|| "recovery request failed".into()),
            ));
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
        .ok_or_else(errors::no_workspace)?;
    if !automatic {
        drop(session.recovery.range.take());
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
        return Ok(Some(
            match arachne_delivery::wire::verify_reply(owner, &query, &reply)
                .map_err(delivery(ErrorCode::TransportFailed))?
            {
                arachne_delivery::wire::RangeReply::Rejected(error) => {
                    RangeStatus::RecoveryRangeRejected {
                        reason: error.to_string(),
                        accepted_progress: false,
                    }
                }
                arachne_delivery::wire::RangeReply::Offered(range) => {
                    let packet_count = range.packets().len();
                    drop(range);
                    session.recovery.ready_range = Some(ReadyRange {
                        query,
                        peer,
                        reply,
                        packet_count,
                        automatic: false,
                    });
                    range_ready(session.recovery.ready_range.as_ref().unwrap(), None)
                }
            },
        ));
    }
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
            .map_err(|_| from_peer(peer, "reachable holder did not answer"))
            .and_then(|reply| {
                let (query, reply) = match &available {
                    Some(request) => arachne_delivery::wire::parse_available_reply(request, &reply)
                        .map_err(|_| from_peer(peer, "holder returned invalid recovery evidence"))?
                        .ok_or_else(|| from_peer(peer, "holder has no retained range"))?,
                    None => (query.clone(), reply),
                };
                match arachne_delivery::wire::verify_reply(owner, &query, &reply) {
                    Ok(arachne_delivery::wire::RangeReply::Offered(range)) => {
                        Ok((query, reply, range.packets().len()))
                    }
                    Ok(arachne_delivery::wire::RangeReply::Rejected(error)) => {
                        Err(from_peer(peer, &error.to_string()))
                    }
                    Err(_) => Err(from_peer(peer, "holder returned invalid recovery evidence")),
                }
            })
    });
    match result {
        Ok((query, reply, packet_count)) => {
            drop(session.recovery.range.take());
            session.recovery.ready_range = Some(ReadyRange {
                query,
                peer,
                reply,
                packet_count,
                automatic: true,
            });
            Ok(Some(range_ready(
                session.recovery.ready_range.as_ref().unwrap(),
                Some(attempted),
            )))
        }
        Err(error) => {
            session.recovery.range.as_mut().unwrap().reason = Some(errors::legacy_text(&error));
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Direct recovery
// ---------------------------------------------------------------------------

pub(crate) fn next_direct_gap(session: &mut Session) -> Result<Option<DirectGap>, ApiError> {
    let gap = session
        .delivery
        .inbox
        .as_ref()
        .ok_or_else(|| ApiError::wrong_state("object delivery not enabled"))?
        .next_direct_gap(
            session
                .workspace
                .as_ref()
                .ok_or_else(errors::no_workspace)?,
        )
        .map_err(delivery(ErrorCode::Internal))?;
    Ok(gap.map(|gap| DirectGap {
        state: "direct_recovery_needed",
        author: gap.author,
        revision: gap.revision,
        topic: gap.topic.as_str().to_owned(),
        recipients: gap.recipients,
        after: gap.after,
        through: gap.through,
    }))
}

/// Ask the intended recipients (and the author) for a direct range.
pub(crate) fn fetch_direct(session: &mut Session, args: FetchDirectArgs) -> Result<DirectStatus, ApiError> {
    let FetchDirectArgs {
        author,
        revision,
        topic,
        recipients,
        after,
        through,
    } = args;
    if busy(session) {
        return Err(ApiError::wrong_state("continuity operation already pending"));
    }
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let local = owner
        .member()
        .ok_or_else(|| ApiError::wrong_state("member required"))?
        .id();
    if session.delivery.inbox.is_none()
        || !recipients.contains(&local)
        || recipients.len() > 64
        || recipients.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ApiError::invalid_input(
            "recipients",
            "invalid direct recovery audience",
        ));
    }
    let query = arachne_delivery::wire::DirectRangeQuery {
        workspace: owner.id(),
        author,
        epoch: owner.epoch(),
        policy_revision: revision,
        topic: Topic::new(topic).map_err(errors::routing)?,
        recipients,
        after,
        through,
    };
    session.recovery.direct_miss = None;
    let wire = query.to_wire().map_err(delivery(ErrorCode::InvalidInput))?;
    let topics = BTreeSet::from([query.topic.clone()]);
    let mut candidates = owner
        .endpoints_for_members(&query.recipients)
        .map_err(security(ErrorCode::NotMember))?;
    candidates.extend(
        owner
            .endpoints_for_members(&[query.author])
            .map_err(security(ErrorCode::NotMember))?,
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
        return Ok(DirectStatus::DirectRecoverySourceWaiting {
            accepted_progress: false,
        });
    }
    let (candidate_count, replies, task) = ask_holders(session, &candidates, &wire);
    session.recovery.direct_range = Some(PendingDirectRange {
        query,
        replies,
        task,
        attempted: 0,
        reason: None,
    });
    Ok(DirectStatus::DirectRecoveryPending {
        candidate_count,
        accepted_progress: false,
    })
}

pub(crate) fn cancel_direct(session: &mut Session) -> Result<DirectStatus, ApiError> {
    drop(session.recovery.direct_range.take());
    session.recovery.ready_direct_range = None;
    session.recovery.direct_miss = None;
    Ok(DirectStatus::DirectRecoveryCancelled {
        accepted_progress: false,
    })
}

pub(crate) fn poll_direct(session: &mut Session) -> Result<Option<DirectStatus>, ApiError> {
    let Some(active) = session.recovery.direct_range.as_mut() else {
        return Ok(None);
    };
    let (peer, reply) = match active.replies.try_recv() {
        Ok(reply) => reply,
        Err(mpsc::error::TryRecvError::Empty) if !active.task.is_finished() => {
            return Ok(None);
        }
        Err(_) => {
            let mut pending = session.recovery.direct_range.take().unwrap();
            session.recovery.direct_miss = Some(pending.query.clone());
            return Ok(Some(DirectStatus::DirectRecoverySourceUnavailable {
                attempted: pending.attempted,
                reason: pending.reason.take().unwrap_or_else(|| {
                    "no intended recipient supplied the missing range".into()
                }),
                accepted_progress: false,
            }));
        }
    };
    active.attempted += 1;
    let query = active.query.clone();
    let attempted = active.attempted;
    let result = reply.and_then(|reply| {
        let owner = session
            .workspace
            .as_ref()
            .ok_or_else(errors::no_workspace)?;
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
            .map_err(delivery(ErrorCode::TransportFailed))?
        {
            arachne_delivery::wire::DirectRangeReply::Offered(packets) => {
                Ok((reply, packets.len()))
            }
            arachne_delivery::wire::DirectRangeReply::Unavailable => Err(from_peer(
                peer,
                "intended recipient has no retained range",
            )),
        }
    });
    match result {
        Ok((reply, packet_count)) => {
            drop(session.recovery.direct_range.take());
            session.recovery.ready_direct_range = Some(ReadyDirectRange {
                query,
                peer,
                reply,
                packet_count,
            });
            let ready = session.recovery.ready_direct_range.as_ref().unwrap();
            Ok(Some(DirectStatus::DirectRecoveryReady {
                workspace: ready.query.workspace,
                author: ready.query.author,
                peer: ready.peer,
                epoch: ready.query.epoch,
                revision: ready.query.policy_revision,
                topic: ready.query.topic.as_str().to_owned(),
                after: ready.query.after,
                through: ready.query.through,
                packet_count: ready.packet_count,
                retained_bytes: ready.reply.len(),
                attempted,
                accepted_progress: false,
            }))
        }
        Err(error) => {
            session.recovery.direct_range.as_mut().unwrap().reason =
                Some(errors::legacy_text(&error));
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Current view
// ---------------------------------------------------------------------------

/// Ask for an authority's current values of one selector.
pub(crate) fn fetch_current_view(
    session: &mut Session,
    args: FetchCurrentViewArgs,
) -> Result<CurrentViewStatus, ApiError> {
    let FetchCurrentViewArgs {
        peer,
        authority,
        revision,
        topic,
        selector,
    } = args;
    if busy(session) {
        return Err(ApiError::wrong_state("continuity operation already pending"));
    }
    if peer == Some(session.node.id()) || session.delivery.inbox.is_none() {
        return Err(ApiError::invalid_input("peer", "invalid current-view request"));
    }
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let topic = Topic::new(topic).map_err(errors::routing)?;
    let topics = BTreeSet::from([topic.clone()]);
    let authority_endpoint = owner
        .endpoints_for_members(&[authority])
        .map_err(security(ErrorCode::NotMember))?[0];
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
        return Ok(CurrentViewStatus::CurrentViewSourceWaiting {
            accepted_progress: false,
        });
    }
    let wire = query.to_wire().map_err(delivery(ErrorCode::InvalidInput))?;
    let (candidate_count, replies, task) = ask_holders(session, &candidates, &wire);
    session.recovery.current_view = Some(PendingCurrentView {
        query,
        automatic,
        replies,
        task,
        attempted: 0,
        reason: None,
        best: None,
    });
    Ok(CurrentViewStatus::CurrentViewPending {
        candidate_count,
        automatic_source: automatic,
        accepted_progress: false,
    })
}

/// Collect the answers; once all are in, the best verified view is ready.
pub(crate) fn poll_current_view(session: &mut Session) -> Result<Option<CurrentViewStatus>, ApiError> {
    let Some(mut active) = session.recovery.current_view.take() else {
        return Ok(None);
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
                .and_then(|_| reply.map_err(|_| from_peer(peer, "reachable holder did not answer")))
                .and_then(|reply| {
                    let owner = session
                        .workspace
                        .as_ref()
                        .ok_or_else(errors::no_workspace)?;
                    arachne_delivery::current::verify_wire_reply(owner, &query, &reply)
                        .map_err(|_| from_peer(peer, "holder returned invalid current-view evidence"))
                        .and_then(|view| {
                            view.map(|view| (reply, view))
                                .ok_or_else(|| from_peer(peer, "holder has no current view"))
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
                    Err(reason) => active.reason = Some(errors::legacy_text(&reason)),
                }
            }
            Err(mpsc::error::TryRecvError::Empty) if !active.task.is_finished() => {
                session.recovery.current_view = Some(active);
                return Ok(None);
            }
            Err(_) => break,
        }
    }
    let attempted = active.attempted;
    if let Some(ready) = active.best.take() {
        let cut = ready.cut;
        let value_count = ready.value_count;
        session.recovery.ready_current_view = Some(ready);
        Ok(Some(CurrentViewStatus::CurrentViewReady {
            cut,
            value_count,
            automatic_source: automatic,
            attempted,
            accepted_progress: false,
        }))
    } else if automatic {
        Ok(Some(CurrentViewStatus::CurrentViewUnavailable {
            attempted: Some(attempted),
            reason: active.reason.take().unwrap_or_else(|| {
                "no current holder supplied an authenticated view".into()
            }),
            automatic_source: true,
            accepted_progress: false,
        }))
    } else if active.reason.as_deref() == Some("holder has no current view") {
        Ok(Some(CurrentViewStatus::CurrentViewUnavailable {
            attempted: None,
            reason: active.reason.take().unwrap(),
            automatic_source: false,
            accepted_progress: false,
        }))
    } else {
        Err(ApiError::transport_failed(
            None,
            active
                .reason
                .take()
                .unwrap_or_else(|| "current-view request failed".into()),
        ))
    }
}

/// Stage the ready current view into the inbox.
pub(crate) fn stage_current_view(session: &mut Session) -> Result<StagedRecovery, ApiError> {
    let (query, peer, reply, cut) = {
        let ready = session
            .recovery
            .ready_current_view
            .as_ref()
            .ok_or_else(|| ApiError::wrong_state("no current view ready"))?;
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
        .ok_or_else(errors::no_workspace)?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    let now = arachne_delivery::UnixSeconds::now().map_err(delivery(ErrorCode::Internal))?;
    let (mut inbox, pending, stale) = session
        .delivery
        .inbox
        .as_ref()
        .ok_or_else(|| ApiError::wrong_state("object delivery not enabled"))?
        .accept_current_view(owner, &query, &reply, now)
        .map_err(delivery(ErrorCode::InvalidInput))?;
    if arachne_delivery::current::verify_wire_reply(owner, &query, &reply)
        .map_err(delivery(ErrorCode::InvalidInput))?
        .is_some_and(|view| {
            view.values
                .iter()
                .any(|value| now.before_remote_expiry(value.expires_at))
        })
    {
        inbox = inbox
            .retain_current_view(owner, &query, &reply, now)
            .map_err(delivery(ErrorCode::InvalidInput))?;
    }
    let publisher = match &session.delivery.publisher {
        Some(publisher) => publisher.clone(),
        None => arachne_delivery::PublisherLog::new(owner).map_err(delivery(ErrorCode::Internal))?,
    };
    let snapshot = seal_state(
        session.records.is_some(),
        owner,
        key,
        Some(&publisher),
        Some(&inbox),
    )?;
    let candidate = owner
        .provisional_copy()
        .map_err(security(ErrorCode::Internal))?;
    let workspace = owner.id();
    session.transition.staged = Some(StagedWorkspace {
        publisher: Some(publisher),
        inbox: Some(inbox),
        transition: WorkspaceTransition::CurrentView {
            cut,
            pending,
            stale,
        },
        workspace: candidate,
        snapshot: snapshot.clone(),
    });
    session.recovery.ready_current_view = None;
    Ok(StagedRecovery {
        workspace,
        snapshot,
        state: "awaiting_current_view_save",
        publication_count: None,
        missing_count: None,
        accepted_through: None,
        current_view: Some(crate::ops::candidate::CurrentViewCounts {
            cut,
            pending,
            stale,
        }),
        durable: false,
        accepted_progress: false,
    })
}

pub(crate) fn cancel_current_view(session: &mut Session) -> Result<CurrentViewStatus, ApiError> {
    drop(session.recovery.current_view.take());
    session.recovery.ready_current_view = None;
    Ok(CurrentViewStatus::CurrentViewCancelled {
        accepted_progress: false,
    })
}

// ---------------------------------------------------------------------------
// Cutoff
// ---------------------------------------------------------------------------

/// Ask `peer` for the retained window of its own publications.
pub(crate) fn discover_cutoff(session: &mut Session, args: CutoffArgs) -> Result<CutoffStatus, ApiError> {
    let CutoffArgs {
        peer,
        revision,
        topics,
        epoch,
    } = args;
    if busy(session) {
        return Err(ApiError::wrong_state("recovery operation already pending"));
    }
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    if peer == session.node.id() || topics.is_empty() || topics.len() > arachne_delivery::MAX_TOPICS {
        return Err(ApiError::invalid_input(
            "peer",
            "invalid recovery peer or selection",
        ));
    }
    let topics = topic_set(topics)?;
    let epoch = recovery_epoch(owner, epoch)?;
    let expected = owner
        .recovery_cutoff_request(peer, arachne_delivery::selection_digest(&topics), revision)
        .map_err(security(ErrorCode::InvalidInput))?;
    let query = arachne_delivery::wire::CutoffQuery {
        workspace: expected.workspace,
        author: expected.author,
        epoch,
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
        session.node.request_control(
            peer,
            &query.to_wire().map_err(delivery(ErrorCode::InvalidInput))?,
        ),
    );
    session.recovery.cutoff = Some(PendingControl { query, peer, task });
    Ok(CutoffStatus::RecoveryCutoffPending {
        accepted_progress: false,
    })
}

pub(crate) fn poll_cutoff(session: &mut Session) -> Result<Option<CutoffStatus>, ApiError> {
    if !session
        .recovery
        .cutoff
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        return Ok(None);
    }
    // Consume once, including errors. No session lock was held by the task.
    let mut pending = session.recovery.cutoff.take().unwrap();
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
        .map_err(errors::task("recovery cutoff task cancelled"))?
        .map_err(errors::node)?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let head = if reply == arachne_delivery::wire::denied_reply() {
        None
    } else {
        Some(
            owner
                .verify_recovery_window(
                    &pending
                        .query
                        .request()
                        .map_err(delivery(ErrorCode::Internal))?,
                    &reply,
                )
                .map_err(security(ErrorCode::TransportFailed))?,
        )
    };
    let query = &pending.query;
    Ok(Some(match head {
        Some((after, head)) => {
            let accepted_through = session.delivery.inbox.as_ref().map_or(0, |inbox| {
                inbox.recovery_progress(query.author, query.epoch, &query.topics)
            });
            CutoffStatus::RecoveryCutoffObserved {
                workspace: owner.id(),
                author: query.author,
                peer: pending.peer,
                epoch: query.epoch,
                revision: query.policy_revision,
                topics: query.topics.iter().map(|topic| topic.as_str().to_owned()).collect(),
                head,
                retained_after: after,
                accepted_through,
                accepted_progress: false,
            }
        }
        None => CutoffStatus::RecoveryCutoffDenied {
            accepted_progress: false,
        },
    }))
}

// ---------------------------------------------------------------------------
// Staging recovered objects
// ---------------------------------------------------------------------------

fn nothing(state: &'static str) -> RecoveryStaged {
    RecoveryStaged::Nothing(NothingStaged {
        state,
        accepted_through: None,
        accepted_progress: None,
    })
}

/// Stage only a locally requested, verified range; no caller-supplied reply bytes.
pub(crate) fn stage_range(session: &mut Session, args: StageRangeArgs) -> Result<RecoveryStaged, ApiError> {
    let retain_until = args.retain_until;
    let ready = session
        .recovery
        .ready_range
        .as_ref()
        .ok_or_else(|| ApiError::wrong_state("no recovery range ready"))?;
    check_recovery_policy(
        session,
        ready.peer,
        ready.query.author,
        ready.query.workspace,
        ready.query.epoch,
        ready.query.policy_revision,
        &ready.query.topics,
    )?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    let publisher = publisher_or_new(session, owner)?;
    let fresh;
    let inbox = match session.delivery.inbox.as_ref() {
        Some(inbox) => inbox,
        None => {
            fresh = arachne_delivery::inbox::ObjectInbox::new(owner.id(), owner.epoch());
            &fresh
        }
    };
    if ready.automatic {
        let progress =
            inbox.recovery_progress(ready.query.author, ready.query.epoch, &ready.query.topics);
        if ready.query.through <= progress {
            session.recovery.ready_range = None;
            return Ok(nothing("recovery_already_covered"));
        }
        if ready.query.after != progress {
            return Err(ApiError::candidate_stale(
                "recovery range does not continue accepted progress",
            ));
        }
    }
    let offer = match arachne_delivery::wire::verify_reply(owner, &ready.query, &ready.reply)
        .map_err(delivery(ErrorCode::TransportFailed))?
    {
        arachne_delivery::wire::RangeReply::Offered(offer) => offer,
        arachne_delivery::wire::RangeReply::Rejected(error) => {
            return Err(from_peer(ready.peer, &error.to_string()));
        }
    };
    let mut next = inbox.clone();
    if retain_until != 0 {
        let now = arachne_delivery::UnixSeconds::now().map_err(delivery(ErrorCode::Internal))?;
        next = next
            .retain_range(owner, &ready.query, &ready.reply, retain_until, now)
            .map_err(delivery(ErrorCode::InvalidInput))?;
    }
    let mut count = 0;
    // B7b: the whole range is verified above. Automatic recovery admits
    // the longest in-order prefix that fits the pending bounds and claims
    // progress only through its last record. The first refused record and
    // all after it are not recorded; a later request after the
    // application drains brings them again.
    let mut covered = ready.query.after;
    let mut stopped = false;
    for packet in offer.packets() {
        let live = packet
            .ciphertext
            .starts_with(b"DFVL")
            .then(|| arachne_delivery::current::LiveCurrentPacket::from_wire(&packet.ciphertext))
            .transpose()
            .map_err(delivery(ErrorCode::TransportFailed))?;
        let ciphertext = if let Some(live) = &live {
            let (context, ciphertext) = PublicationContext::unpack(
                packet.context.workspace,
                packet.context.revision,
                packet.context.topic.clone(),
                &live.packet,
            )
            .map_err(|reason| from_peer(ready.peer, reason))?;
            if context != packet.context {
                return Err(from_peer(
                    ready.peer,
                    "retained current publication context mismatch",
                ));
            }
            ciphertext
        } else {
            packet.ciphertext.as_slice()
        };
        let aad = live.as_ref().map_or_else(
            || packet.context.authenticated_bytes(),
            |live| live.metadata.authenticated_context(&packet.context),
        );
        let authenticated = owner
            .unprotect_object(packet.context.topic.namespace().as_bytes(), &aad, ciphertext)
            .map_err(security(ErrorCode::NotAuthorized))?;
        offer
            .verify_origin(&authenticated.message)
            .map_err(delivery(ErrorCode::NotAuthorized))?;
        let staged = match live {
            Some(ref live) => next.stage_live_current(owner, &packet.context, live.metadata, ciphertext),
            None => next.stage(owner, &packet.context, ciphertext),
        };
        let staged = match staged {
            Err(error)
                if ready.automatic && arachne_delivery::inbox::drains_with_application(error) =>
            {
                stopped = true;
                break;
            }
            staged => staged.map_err(delivery(ErrorCode::InvalidInput))?,
        };
        match staged {
            arachne_delivery::inbox::InboxStage::Prepared(candidate) => {
                next = *candidate;
                count += 1;
            }
            arachne_delivery::inbox::InboxStage::Duplicate => (),
            arachne_delivery::inbox::InboxStage::OutsideWindow => {
                return Err(ApiError::epoch_mismatch(
                    "recovered object outside receive window",
                ));
            }
        }
        covered = packet
            .context
            .sequence
            .ok_or_else(|| from_peer(ready.peer, "recovered publication lacks sequence"))?
            .get();
    }
    if !stopped {
        covered = ready.query.through;
    }
    if ready.automatic && covered > ready.query.after {
        next = next
            .accept_recovery_prefix(owner, &ready.query, &ready.reply, covered)
            .map_err(delivery(ErrorCode::InvalidInput))?;
    }
    if count == 0 && retain_until == 0 && !ready.automatic {
        session.recovery.ready_range = None;
        return Ok(nothing("recovery_no_new_objects"));
    }
    if ready.automatic && covered == ready.query.after && retain_until == 0 {
        // Nothing fits until the application drains this author's
        // pending objects. No progress is claimed; request again later.
        session.recovery.ready_range = None;
        return Ok(RecoveryStaged::Nothing(NothingStaged {
            state: "recovery_awaiting_application",
            accepted_through: Some(covered),
            accepted_progress: Some(false),
        }));
    }
    let automatic = ready.automatic;
    let snapshot = seal_state(session.records.is_some(), owner, key, Some(&publisher), Some(&next))?;
    let candidate = owner
        .provisional_copy()
        .map_err(security(ErrorCode::Internal))?;
    let value = StagedRecovery {
        workspace: owner.id(),
        snapshot: snapshot.clone(),
        state: "awaiting_recovery_save",
        publication_count: Some(count),
        missing_count: missed_since_commit(session, Some(&next)),
        accepted_through: automatic.then_some(covered),
        current_view: None,
        durable: false,
        accepted_progress: false,
    };
    session.transition.staged = Some(StagedWorkspace {
        workspace: candidate,
        publisher: Some(publisher),
        inbox: Some(next),
        snapshot,
        transition: WorkspaceTransition::InboxRecovery { count },
    });
    session.recovery.ready_range = None;
    Ok(RecoveryStaged::Candidate(value))
}

/// Stage the ready direct range: its in-order prefix (B7c).
pub(crate) fn stage_direct(session: &mut Session) -> Result<RecoveryStaged, ApiError> {
    let ready = session
        .recovery
        .ready_direct_range
        .as_ref()
        .ok_or_else(|| ApiError::wrong_state("no direct recovery range ready"))?;
    check_recovery_policy(
        session,
        ready.peer,
        ready.query.author,
        ready.query.workspace,
        ready.query.epoch,
        ready.query.policy_revision,
        &BTreeSet::from([ready.query.topic.clone()]),
    )?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    // B7c: a partial range is admitted as its in-order prefix; the stream
    // keeps its gap for the rest. When nothing fits, nothing is staged.
    let (next, count) = match session
        .delivery
        .inbox
        .as_ref()
        .ok_or_else(|| ApiError::wrong_state("no object delivery state"))?
        .stage_direct_range(owner, &ready.query, &ready.reply)
    {
        Err(error) if arachne_delivery::inbox::drains_with_application(error) => {
            session.recovery.ready_direct_range = None;
            return Ok(RecoveryStaged::Nothing(NothingStaged {
                state: "direct_recovery_awaiting_application",
                accepted_through: None,
                accepted_progress: Some(false),
            }));
        }
        staged => staged.map_err(delivery(ErrorCode::InvalidInput))?,
    };
    if count == 0 {
        session.recovery.ready_direct_range = None;
        return Ok(nothing("direct_recovery_already_covered"));
    }
    let publisher = publisher_or_new(session, owner)?;
    let snapshot = seal_state(session.records.is_some(), owner, key, Some(&publisher), Some(&next))?;
    let candidate = owner
        .provisional_copy()
        .map_err(security(ErrorCode::Internal))?;
    let value = StagedRecovery {
        workspace: owner.id(),
        snapshot: snapshot.clone(),
        state: "awaiting_recovery_save",
        publication_count: Some(count),
        missing_count: missed_since_commit(session, Some(&next)),
        accepted_through: None,
        current_view: None,
        durable: false,
        accepted_progress: false,
    };
    session.transition.staged = Some(StagedWorkspace {
        workspace: candidate,
        publisher: Some(publisher),
        inbox: Some(next),
        snapshot,
        transition: WorkspaceTransition::InboxRecovery { count },
    });
    session.recovery.ready_direct_range = None;
    Ok(RecoveryStaged::Candidate(value))
}

/// Give up the exhausted direct gap and record it as missed.
pub(crate) fn stage_direct_miss(session: &mut Session) -> Result<StagedRecovery, ApiError> {
    let query = session
        .recovery
        .direct_miss
        .as_ref()
        .ok_or_else(|| ApiError::wrong_state("no exhausted direct recovery ready"))?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    let (next, missing) = session
        .delivery
        .inbox
        .as_ref()
        .ok_or_else(|| ApiError::wrong_state("no object delivery state"))?
        .skip_direct_gap(owner, query)
        .map_err(delivery(ErrorCode::InvalidInput))?;
    let publisher = publisher_or_new(session, owner)?;
    let snapshot = seal_state(session.records.is_some(), owner, key, Some(&publisher), Some(&next))?;
    let candidate = owner
        .provisional_copy()
        .map_err(security(ErrorCode::Internal))?;
    let value = StagedRecovery {
        workspace: owner.id(),
        snapshot: snapshot.clone(),
        state: "awaiting_recovery_save",
        publication_count: None,
        missing_count: Some(missing),
        accepted_through: None,
        current_view: None,
        durable: false,
        accepted_progress: false,
    };
    session.transition.staged = Some(StagedWorkspace {
        workspace: candidate,
        publisher: Some(publisher),
        inbox: Some(next),
        snapshot,
        transition: WorkspaceTransition::DirectMiss { missing },
    });
    session.recovery.direct_miss = None;
    Ok(value)
}

// ---------------------------------------------------------------------------
// Serving peers
// ---------------------------------------------------------------------------

/// A peer's continuity query: range, available range, cutoff, current view
/// or direct range.
pub(crate) fn is_query(payload: &[u8]) -> bool {
    payload.starts_with(b"DFRQ")
        || payload.starts_with(b"DFHQ")
        || payload.starts_with(b"DFCQ")
        || payload.starts_with(b"DFVQ")
        || payload.starts_with(b"DFDQ")
}

/// Answer one continuity query from committed state. Never serves staged
/// state (the guards reject polls while adoption is pending).
pub(crate) fn serve(
    session: &mut Session,
    incoming: arachne_node::ControlRequest,
) -> Result<Value, ApiError> {
    let reply = match session.workspace.as_ref() {
        Some(owner) => {
            let now = arachne_delivery::UnixSeconds::now().map_err(delivery(ErrorCode::Internal))?;
            session
                .runtime
                .block_on(session.node.with_routing_policy(|policy| {
                    if incoming.payload().starts_with(b"DFDQ") {
                        match (
                            session.delivery.inbox.as_ref(),
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
                            session.delivery.inbox.as_ref(),
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
                            session.delivery.publisher.as_ref(),
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
                            match session.delivery.publisher.as_ref() {
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
                            match session.delivery.inbox.as_ref() {
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
                            match session.delivery.publisher.as_ref() {
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
                            match session.delivery.inbox.as_ref() {
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
                .map_err(delivery(ErrorCode::Internal))?
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
    incoming.respond(reply).map_err(errors::node)?;
    Ok(json!({"state":state, "remote_receipt":false}))
}
