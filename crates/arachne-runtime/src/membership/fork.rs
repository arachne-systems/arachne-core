//! Fork choice and retained pre-commit state (ADR A2). Peers carry hints;
//! only steps verified against our own history can replace authority.
use super::*;
use arachne_security::{
    BranchDecision, BranchState, PreparedManagementUpdate, SecurityRecords, Workspace,
};
use zeroize::Zeroizing;

pub(crate) const PREFIX: &[u8] = b"runtime/branch/";
const META: &[u8] = b"runtime/branch/meta";
const SNAPSHOT: &[u8] = b"runtime/branch/snapshot/";

#[derive(Default)]
pub(crate) struct ForkState {
    pub(crate) retained: Option<BranchState>,
    candidate: Option<(Vec<u8>, BranchState)>,
    query: Option<PendingControl<wire::BranchQuery>>,
    pull: Option<PendingControl<wire::RangeQuery>>,
}

impl ForkState {
    pub(crate) fn has_result(&self) -> bool {
        self.query
            .as_ref()
            .is_some_and(|job| job.task.is_finished())
            || self.pull.as_ref().is_some_and(|job| job.task.is_finished())
    }
    pub(crate) fn is_running(&self) -> bool {
        self.query.is_some() || self.pull.is_some()
    }
}

/// Attach the pre-commit snapshot to the exact candidate token. Both save
/// and adopt call this; once prepared, neither recreates its sealed bytes.
pub(crate) fn prepare_candidate(session: &mut Session) -> Result<(), ApiError> {
    let Some(staged) = &session.transition.staged else {
        return Ok(());
    };
    if session
        .membership
        .fork
        .candidate
        .as_ref()
        .is_some_and(|(token, _)| *token == staged.snapshot)
    {
        return Ok(());
    }
    let mut branch = session.membership.fork.retained.clone().unwrap_or_else(|| {
        BranchState::new(
            session
                .workspace
                .as_ref()
                .map_or(staged.workspace.epoch(), |owner| owner.epoch()),
        )
    });
    if let Some(previous) = &session.workspace
        && staged.workspace.epoch() > previous.epoch()
        && branch.snapshot(previous.epoch()).is_none()
    {
        let key = persistence::record_key(session)?;
        match previous.seal_branch_snapshot(&key) {
            Ok(snapshot) => branch
                .retain(previous.epoch(), snapshot)
                .map_err(security(ErrorCode::StorageFailed))?,
            // Retention limits shorten the rollback window, not membership
            // progress. A later losing fork below this mark becomes orphaned.
            Err("branch snapshot exceeds size limit") => branch.settle_through(previous.epoch()),
            Err(reason) => return Err(security(ErrorCode::StorageFailed)(reason)),
        }
    }
    session.membership.fork.candidate = Some((staged.snapshot.clone(), branch));
    Ok(())
}

pub(crate) fn adopt_candidate(session: &mut Session, token: &[u8]) -> Result<(), ApiError> {
    let (expected, branch) = session
        .membership
        .fork
        .candidate
        .take()
        .ok_or_else(|| ApiError::candidate_stale("branch candidate is missing"))?;
    if expected != token {
        return Err(ApiError::candidate_stale(
            "branch candidate does not match workspace candidate",
        ));
    }
    session.membership.fork.retained = Some(branch);
    Ok(())
}

/// Records are part of the same encrypted-store transaction as the owner.
pub(crate) fn records(session: &Session, candidate: bool) -> Result<SecurityRecords, ApiError> {
    let branch = if candidate {
        session
            .membership
            .fork
            .candidate
            .as_ref()
            .map(|(_, branch)| branch)
    } else {
        session.membership.fork.retained.as_ref()
    };
    let initial;
    let branch = match branch {
        Some(branch) => branch,
        None => {
            let Some(owner) = &session.workspace else {
                return Ok(SecurityRecords::new());
            };
            initial = BranchState::new(owner.epoch());
            &initial
        }
    };
    let mut records =
        SecurityRecords::from([(META.to_vec(), Zeroizing::new(branch.meta_record()))]);
    for (epoch, sealed) in branch.snapshots() {
        let mut name = SNAPSHOT.to_vec();
        name.extend(epoch.to_be_bytes());
        records.insert(name, Zeroizing::new(sealed.to_vec()));
    }
    Ok(records)
}

pub(crate) fn restore(session: &mut Session, records: &SecurityRecords) -> Result<(), ApiError> {
    let Some(meta) = records.get(META) else {
        if records.is_empty() {
            return Ok(());
        }
        return Err(ApiError::storage_corrupt("missing branch metadata"));
    };
    let mut snapshots = Vec::new();
    for (name, value) in records {
        if name == META {
            continue;
        }
        let epoch = name
            .strip_prefix(SNAPSHOT)
            .filter(|tail| tail.len() == 8)
            .ok_or_else(|| ApiError::storage_corrupt("invalid branch record name"))?;
        snapshots.push((
            u64::from_be_bytes(epoch.try_into().unwrap()),
            value.to_vec(),
        ));
    }
    let branch =
        BranchState::from_parts(meta, &snapshots).map_err(security(ErrorCode::StorageCorrupt))?;
    session.membership.fork.retained = Some(branch);
    Ok(())
}

pub(crate) fn require_send(session: &Session) -> Result<(), ApiError> {
    if session
        .membership
        .fork
        .retained
        .as_ref()
        .is_some_and(BranchState::is_orphaned)
    {
        return Err(ApiError::wrong_state(
            "workspace branch is orphaned; administrator re-add required",
        ));
    }
    Ok(())
}

/// Compare one conflicting step at its parent epoch. The remote class is
/// computed only after public verification against our chain at the fork.
pub(crate) fn stage(session: &mut Session, epoch: u64, step: JoinStep) -> Result<Value, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let (authorization, commit) = step.parts()?;
    let local = owner
        .branch_key(epoch)
        .map_err(security(ErrorCode::InvalidInput))?
        .ok_or_else(|| ApiError::invalid_input("step", "fork is outside retained step history"))?;
    let remote = owner
        .verify_branch_step(epoch, &authorization, &commit)
        .map_err(security(ErrorCode::InvalidInput))?;
    let initial = BranchState::new(owner.epoch());
    let branch = session
        .membership
        .fork
        .retained
        .as_ref()
        .unwrap_or(&initial);
    let (next, branch, publisher, inbox) = match branch.resolve(epoch, local, remote) {
        BranchDecision::Keep => return Ok(json!({"state":"membership_branch_kept"})),
        BranchDecision::Orphaned(branch) => (
            owner
                .provisional_copy()
                .map_err(security(ErrorCode::StorageCorrupt))?,
            branch,
            session.delivery.publisher.clone(),
            session.delivery.inbox.clone(),
        ),
        BranchDecision::Switch(prepared) => {
            let key = persistence::record_key(session)?;
            let mut at_fork = Workspace::restore_branch_snapshot(
                &key,
                owner.endpoint(),
                owner.id(),
                prepared.snapshot(),
            )
            .map_err(security(ErrorCode::StorageCorrupt))?;
            if at_fork.epoch() != epoch {
                return Err(ApiError::storage_corrupt(
                    "branch snapshot has the wrong epoch",
                ));
            }
            at_fork
                .restore_branch_history(owner)
                .map_err(security(ErrorCode::StorageCorrupt))?;
            let next = match at_fork
                .prepare_step_update(&authorization, &commit)
                .map_err(security(ErrorCode::InvalidInput))?
            {
                PreparedManagementUpdate::Active(next) => *next,
                PreparedManagementUpdate::Removed(removed) => {
                    return serde_json::to_value(stage_removal(session, removed)?)
                        .map_err(errors::encode);
                }
            };
            let publisher = session
                .delivery
                .publisher
                .as_ref()
                .map(|publisher| {
                    publisher
                        .rebase(owner, &at_fork, &next)
                        .map(|(kept, _)| kept)
                })
                .transpose()
                .map_err(crate::errors::delivery(ErrorCode::StorageCorrupt))?;
            let inbox = session
                .delivery
                .inbox
                .as_ref()
                .map(|inbox| inbox.rebase(owner, epoch, &next))
                .transpose()
                .map_err(crate::errors::delivery(ErrorCode::StorageCorrupt))?;
            (next, prepared.into_parts().1, publisher, inbox)
        }
    };
    let orphaned = branch.is_orphaned();
    let snapshot = seal_state(session.records.is_some())?;
    let mut value = serde_json::to_value(StagedCandidate::new(
        next.id(),
        next.workspace_name()
            .map_err(security(ErrorCode::StorageCorrupt))?,
        snapshot.clone(),
    ))
    .map_err(errors::encode)?;
    value["branch_state"] = json!(if orphaned {
        "orphaned"
    } else {
        "branch_switch_staged"
    });
    value["fork_epoch"] = json!(epoch);
    session.membership.fork.candidate = Some((snapshot.clone(), branch));
    session.transition.staged = Some(StagedWorkspace {
        publisher,
        inbox,
        transition: WorkspaceTransition::Admission,
        workspace: next,
        snapshot,
    });
    session.membership.staged_step_received = true;
    session.membership.steps_ahead.clear();
    session.membership.range_pull = None;
    Ok(value)
}

/// Serve only the public steps this authenticated peer may already read.
pub(crate) fn reply(owner: Option<&Workspace>, peer: [u8; 32], bytes: &[u8]) -> Vec<u8> {
    let build = || -> Result<Vec<u8>, ApiError> {
        let owner = owner.ok_or_else(errors::no_workspace)?;
        let query = wire::decode_branch_query(bytes).map_err(|reason| ApiError::invalid_input("branch", reason))?;
        if query.workspace != owner.id() {
            return Err(ApiError::not_authorized("wrong workspace"));
        }
        let mut rows = Vec::new();
        for epoch in query.from..query.until.min(owner.epoch()) {
            let Some((auth, commit)) = owner
                .membership_update_for(peer, epoch)
                .map_err(security(ErrorCode::NotMember))?
            else {
                break;
            };
            let key = arachne_security::fork_key(&auth, &commit);
            rows.push(wire::BranchRow {
                epoch,
                class: key.class().to_u8(),
                digest: key.digest(),
            });
            if rows.len() == wire::MAX_BRANCH_ROWS {
                break;
            }
        }
        if rows.is_empty() && owner.member_id_for_endpoint(peer).is_err() {
            return Err(ApiError::not_member("branch query requires a member"));
        }
        let current = owner.member_id_for_endpoint(peer).is_ok();
        wire::encode_branch_reply(&wire::BranchReply {
            workspace: owner.id(),
            from: query.from,
            head: if current {
                owner.epoch()
            } else {
                query.from.saturating_add(rows.len() as u64)
            },
            fingerprint: if current {
                owner.epoch_fingerprint()
            } else {
                [0; 32]
            },
            rows,
        })
        .map_err(|reason| ApiError::invalid_input("branch", reason))
    };
    build().unwrap_or_default()
}

/// A head mismatch is a trigger to ask for history, never authority to switch.
pub(crate) fn start(session: &mut Session, peer: [u8; 32]) {
    let Some(owner) = &session.workspace else {
        return;
    };
    if session.membership.fork.query.is_some()
        || session.membership.fork.pull.is_some()
        || session
            .membership
            .fork
            .retained
            .as_ref()
            .is_some_and(BranchState::is_orphaned)
        || owner.member_id_for_endpoint(peer).is_err()
    {
        return;
    }
    let Ok(from) = owner.history_start() else {
        return;
    };
    query(session, peer, from);
}

fn query(session: &mut Session, peer: [u8; 32], from: u64) {
    let Some(owner) = &session.workspace else {
        return;
    };
    let query = wire::BranchQuery {
        workspace: owner.id(),
        from,
        until: owner.epoch(),
    };
    let Ok(bytes) = wire::encode_branch_query(&query) else {
        return;
    };
    let request = session.node.request_control(peer, &bytes);
    let wake = session.node.control_signal();
    let task = session.runtime.spawn(async move {
        let reply = tokio::time::timeout(RANGE_PULL_TIMEOUT, request)
            .await
            .unwrap_or(Err(arachne_node::Error::Timeout("branch query")));
        wake.notify_one();
        reply
    });
    session.membership.fork.query = Some(PendingControl { peer, query, task });
}

pub(crate) fn poll(session: &mut Session) -> Result<Option<Value>, ApiError> {
    if session
        .membership
        .fork
        .query
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        let mut pending = session.membership.fork.query.take().unwrap();
        let bytes = session
            .runtime
            .block_on(&mut pending.task)
            .ok()
            .and_then(Result::ok);
        if let Some(bytes) = bytes
            && let Ok(reply) = wire::decode_branch_reply(&bytes)
            && reply.workspace == pending.query.workspace
            && reply.from == pending.query.from
            && let Some(owner) = &session.workspace
        {
            let mut distinct = None;
            for row in &reply.rows {
                let Some(local) = owner
                    .branch_key(row.epoch)
                    .map_err(security(ErrorCode::StorageCorrupt))?
                else {
                    break;
                };
                if local.digest() != row.digest {
                    distinct = Some(row.epoch);
                    break;
                }
            }
            if let Some(epoch) = distinct {
                let query = wire::RangeQuery {
                    workspace: owner.id(),
                    after: epoch,
                    until: epoch.saturating_add(1),
                };
                let bytes = wire::encode_range_query(&query).map_err(|reason| ApiError::invalid_input("branch", reason))?;
                let request = session.node.request_control(pending.peer, &bytes);
                let wake = session.node.control_signal();
                let task = session.runtime.spawn(async move {
                    let reply = tokio::time::timeout(RANGE_PULL_TIMEOUT, request)
                        .await
                        .unwrap_or(Err(arachne_node::Error::Timeout("branch step")));
                    wake.notify_one();
                    reply
                });
                session.membership.fork.pull = Some(PendingControl {
                    peer: pending.peer,
                    query,
                    task,
                });
                note_head(session, reply.head, pending.peer);
            } else if reply.rows.len() == wire::MAX_BRANCH_ROWS
                && let Some(next) = reply.rows.last().and_then(|row| row.epoch.checked_add(1))
                && next < pending.query.until
            {
                query(session, pending.peer, next);
            }
        }
    }
    if !session
        .membership
        .fork
        .pull
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        return Ok(None);
    }
    let mut pending = session.membership.fork.pull.take().unwrap();
    let bytes = session
        .runtime
        .block_on(&mut pending.task)
        .ok()
        .and_then(Result::ok);
    if let Some(bytes) = bytes
        && let Ok(reply) = wire::decode_range_reply(&bytes)
        && reply.workspace == pending.query.workspace
        && reply.after == pending.query.after
        && let Some(step) = reply.steps.first()
        && let Ok(step) = join_step_from_wire(step)
    {
        let result = stage(session, reply.after, step)?;
        if session.transition.staged.is_some() || session.transition.removal.is_some() {
            return Ok(Some(result));
        }
    }
    Ok(None)
}
