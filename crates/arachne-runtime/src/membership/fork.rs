//! Fork choice and retained pre-commit state (ADR A2). Peers carry hints;
//! only steps verified against our own history can replace authority.
use super::*;
use crate::ops::publication::{CurrentPublication, StagePublicationArgs};
use arachne_security::{
    BranchDecision, BranchState, MembershipAuthorization, OrderStep, PreparedManagementUpdate,
    SecurityRecords, Workspace,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub(crate) const PREFIX: &[u8] = b"runtime/branch/";
const META: &[u8] = b"runtime/branch/meta";
const SNAPSHOT: &[u8] = b"runtime/branch/snapshot/";
const ORDER: &[u8] = b"runtime/branch/order/";
const REPUBLICATIONS: &[u8] = b"runtime/branch/republications";
const MAX_REPUBLICATION_BYTES: usize = 512 * 1024;
const MAX_REPUBLICATIONS: usize = 512;
pub(super) const GOSSIP_ORDER: &[u8] = b"DFGO\x01";
const MAX_CARRIED_ORDERS: usize = 64;

struct BranchCandidate {
    token: Vec<u8>,
    branch: BranchState,
    orders: Vec<OrderStep>,
    republications: Vec<StagePublicationArgs>,
}

#[derive(Clone)]
struct EpochView {
    fingerprint: [u8; 32],
    members: Vec<[u8; 32]>,
}

impl EpochView {
    fn of(owner: &Workspace) -> Result<Self, ApiError> {
        Ok(Self {
            fingerprint: owner.epoch_fingerprint(),
            members: owner
                .member_roster()
                .map_err(security(ErrorCode::StorageCorrupt))?
                .iter()
                .map(|member| member.id)
                .collect(),
        })
    }
}

#[derive(Default)]
pub(crate) struct ForkState {
    pub(crate) retained: Option<BranchState>,
    carried: Vec<OrderStep>,
    republications: Vec<StagePublicationArgs>,
    observed: BTreeMap<[u8; 32], (u64, [u8; 32])>,
    views: BTreeMap<u64, EpochView>,
    settlement_pending: bool,
    candidate: Option<BranchCandidate>,
    query: Option<PendingControl<wire::BranchQuery>>,
    pull: Option<PendingControl<wire::RangeQuery>>,
}

impl ForkState {
    pub(crate) fn has_result(&self) -> bool {
        self.settlement_pending
            || self
                .query
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
        .is_some_and(|candidate| candidate.token == staged.snapshot)
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
        let key = session
            .storage_key
            .as_ref()
            .ok_or_else(errors::no_root_key)?;
        match previous.seal_branch_snapshot(key) {
            Ok(snapshot) => branch
                .retain(previous.epoch(), snapshot)
                .map_err(security(ErrorCode::StorageFailed))?,
            // Retention limits shorten the rollback window, not membership
            // progress. A later losing fork below this mark becomes orphaned.
            Err("branch snapshot exceeds size limit") => branch.settle_through(previous.epoch()),
            Err(reason) => return Err(security(ErrorCode::StorageFailed)(reason)),
        }
    }
    let mut orders = Vec::new();
    if let Some(previous) = &session.workspace {
        for order in &session.membership.fork.carried {
            match staged.workspace.advance_revocation(order, previous) {
                Ok(order) => orders.push(order),
                Err(reason) => eprintln!("arachne: carried revocation discarded: {reason}"),
            }
        }
    }
    session.membership.fork.candidate = Some(BranchCandidate {
        token: staged.snapshot.clone(),
        branch,
        orders,
        republications: session.membership.fork.republications.iter().filter(|publication| {
            !matches!(&staged.transition, WorkspaceTransition::Republication(context, ..) if context.id == publication.id)
        }).cloned().collect(),
    });
    Ok(())
}

pub(crate) fn adopt_candidate(session: &mut Session, token: &[u8]) -> Result<(), ApiError> {
    let candidate = session
        .membership
        .fork
        .candidate
        .take()
        .ok_or_else(|| ApiError::candidate_stale("branch candidate is missing"))?;
    if candidate.token != token {
        return Err(ApiError::candidate_stale(
            "branch candidate does not match workspace candidate",
        ));
    }
    session.membership.fork.retained = Some(candidate.branch);
    session.membership.fork.carried = candidate.orders;
    session.membership.fork.republications = candidate.republications;
    let fork = &mut session.membership.fork;
    fork.views.retain(|epoch, _| {
        fork.retained
            .as_ref()
            .is_some_and(|branch| branch.snapshot(*epoch).is_some())
    });
    if let Some(staged) = &session.transition.staged {
        let roster = staged
            .workspace
            .member_roster()
            .map_err(security(ErrorCode::StorageCorrupt))?;
        fork.observed
            .retain(|member, _| roster.iter().any(|row| row.id == *member));
    }
    fork.settlement_pending = true;
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
            .map(|candidate| &candidate.branch)
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
    let orders = if candidate {
        session
            .membership
            .fork
            .candidate
            .as_ref()
            .map(|candidate| candidate.orders.as_slice())
            .unwrap_or_default()
    } else {
        &session.membership.fork.carried
    };
    for order in orders {
        let mut name = ORDER.to_vec();
        name.extend(order.order.digest());
        records.insert(
            name,
            Zeroizing::new(
                order
                    .to_bytes()
                    .map_err(security(ErrorCode::StorageFailed))?,
            ),
        );
    }
    let republications = if candidate {
        session
            .membership
            .fork
            .candidate
            .as_ref()
            .map(|candidate| candidate.republications.as_slice())
            .unwrap_or_default()
    } else {
        &session.membership.fork.republications
    };
    if !republications.is_empty() {
        records.insert(
            REPUBLICATIONS.to_vec(),
            Zeroizing::new(encode_republications(republications)?),
        );
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
    let mut orders = Vec::new();
    let mut republications: Vec<StagePublicationArgs> = Vec::new();
    for (name, value) in records {
        if name == META {
            continue;
        }
        if name == REPUBLICATIONS {
            if value.len() > MAX_REPUBLICATION_BYTES {
                return Err(ApiError::storage_corrupt(
                    "re-publication record exceeds bounds",
                ));
            }
            let bytes = value
                .strip_prefix(b"DFRP\x01")
                .ok_or_else(|| ApiError::storage_corrupt("unsupported re-publication record"))?;
            republications = postcard::from_bytes(bytes)
                .map_err(|_| ApiError::storage_corrupt("invalid re-publication record"))?;
            encode_republications(&republications)?;
            continue;
        }
        if let Some(digest) = name.strip_prefix(ORDER) {
            let order =
                OrderStep::from_bytes(value).map_err(security(ErrorCode::StorageCorrupt))?;
            if digest != order.order.digest()
                || value.len() > MAX_WIRE_STEP
                || orders.len() == MAX_CARRIED_ORDERS
            {
                return Err(ApiError::storage_corrupt(
                    "invalid carried revocation record",
                ));
            }
            orders.push(order);
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
    session.membership.fork.carried = orders;
    session.membership.fork.republications = republications;
    session.membership.fork.settlement_pending = true;
    Ok(())
}

pub(crate) fn require_active_branch(session: &Session) -> Result<(), ApiError> {
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

pub(crate) fn require_send(session: &Session) -> Result<(), ApiError> {
    require_active_branch(session)?;
    if session
        .membership
        .fork
        .carried
        .iter()
        .any(|order| order.order.kind.removes())
    {
        return Err(ApiError::wrong_state(
            "workspace transmission waits for a carried revocation",
        ));
    }
    Ok(())
}

pub(crate) fn has_carried_work(session: &Session) -> bool {
    let own_id = session
        .workspace
        .as_ref()
        .and_then(|owner| owner.member())
        .map(|member| member.id());
    own_id.is_some_and(|id| {
        session
            .membership
            .fork
            .carried
            .iter()
            .any(|order| !(order.order.kind.removes() && order.order.target == id))
    })
}

pub(crate) fn has_republication_work(session: &Session) -> bool {
    !session.membership.fork.republications.is_empty() && require_send(session).is_ok()
}

fn encode_republications(publications: &[StagePublicationArgs]) -> Result<Vec<u8>, ApiError> {
    if publications.len() > MAX_REPUBLICATIONS {
        return Err(ApiError::limit_reached(
            "re-publications",
            MAX_REPUBLICATIONS as u64,
            "re-publication queue is full",
        ));
    }
    let mut bytes = b"DFRP\x01".to_vec();
    bytes.extend(
        postcard::to_allocvec(publications)
            .map_err(|_| ApiError::storage_failed("re-publication encoding failed"))?,
    );
    if bytes.len() > MAX_REPUBLICATION_BYTES {
        return Err(ApiError::limit_reached(
            "re-publication bytes",
            MAX_REPUBLICATION_BYTES as u64,
            "re-publication queue is full",
        ));
    }
    Ok(bytes)
}

/// The caller has verified the member's signed head or authenticated its
/// control reply. A report is counted only after its fingerprint matches
/// locally accepted state at the same epoch.
pub(crate) fn observe(session: &mut Session, member: [u8; 32], epoch: u64, fingerprint: [u8; 32]) {
    let fork = &mut session.membership.fork;
    if fork.observed.get(&member) != Some(&(epoch, fingerprint)) {
        fork.observed.insert(member, (epoch, fingerprint));
        fork.settlement_pending = true;
    }
}

pub(crate) fn stage_settlement(session: &mut Session) -> Result<Option<Value>, ApiError> {
    if !session.membership.fork.settlement_pending
        || session.transition.staged.is_some()
        || session.transition.removal.is_some()
    {
        return Ok(None);
    }
    session.membership.fork.settlement_pending = false;
    let Some(owner) = &session.workspace else {
        return Ok(None);
    };
    let Some(mut branch) = session.membership.fork.retained.clone() else {
        return Ok(None);
    };
    if branch.is_orphaned() {
        return Ok(None);
    }
    let key = session
        .storage_key
        .as_ref()
        .ok_or_else(errors::no_root_key)?;
    let current = EpochView::of(owner)?;
    let own = owner.member().ok_or_else(errors::no_workspace)?.id();
    let views = &mut session.membership.fork.views;
    let mut at = |epoch: u64| -> Result<Option<EpochView>, ApiError> {
        if epoch == owner.epoch() {
            return Ok(Some(current.clone()));
        }
        if let Some(view) = views.get(&epoch) {
            return Ok(Some(view.clone()));
        }
        let Some(snapshot) = branch.snapshot(epoch) else {
            return Ok(None);
        };
        let snapshot =
            Workspace::restore_branch_snapshot(key, owner.endpoint(), owner.id(), snapshot)
                .map_err(security(ErrorCode::StorageCorrupt))?;
        if snapshot.epoch() != epoch {
            return Err(ApiError::storage_corrupt(
                "branch snapshot has the wrong epoch",
            ));
        }
        let view = EpochView::of(&snapshot)?;
        views.insert(epoch, view.clone());
        Ok(Some(view))
    };
    let mut reports = vec![(own, owner.epoch())];
    for (member, (epoch, fingerprint)) in &session.membership.fork.observed {
        if let Some(view) = at(*epoch)?
            && view.fingerprint == *fingerprint
            && view.members.contains(member)
        {
            reports.push((*member, *epoch));
        }
    }
    let mut rosters = Vec::new();
    for epoch in branch.retained_epochs() {
        if let Some(view) = at(epoch)? {
            rosters.push((epoch, view.members))
        }
    }
    let before = branch.first_unsettled();
    for (epoch, members) in rosters {
        branch.settle_reported(epoch, &members, &reports);
    }
    if branch.first_unsettled() == before {
        return Ok(None);
    }
    let orders = session.membership.fork.carried.clone();
    let mut value = stage_orders(session, orders, "branch_settlement_staged")?;
    value["first_unsettled"] = json!(branch.first_unsettled());
    session.membership.fork.candidate.as_mut().unwrap().branch = branch;
    Ok(Some(value))
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
    let mut republications = session.membership.fork.republications.clone();
    let (next, branch, publisher, inbox, orders) = match branch.resolve(epoch, local, remote) {
        BranchDecision::Keep => {
            // A losing commit still carries an independently signed intent.
            // Keep the winning authority, but carry the intent onto it.
            if local != remote
                && let MembershipAuthorization::Revocation(order) = &authorization
                && let Some(snapshot) = branch.snapshot(epoch)
            {
                let key = session
                    .storage_key
                    .as_ref()
                    .ok_or_else(errors::no_root_key)?;
                let mut common =
                    Workspace::restore_branch_snapshot(key, owner.endpoint(), owner.id(), snapshot)
                        .map_err(security(ErrorCode::StorageCorrupt))?;
                if common.epoch() != epoch {
                    return Err(ApiError::storage_corrupt(
                        "branch snapshot has the wrong epoch",
                    ));
                }
                common
                    .restore_branch_history(owner)
                    .map_err(security(ErrorCode::StorageCorrupt))?;
                if let Ok(order) = owner.rebase_revocation(order, owner, &common)
                    && let Some(staged) = receive_order(
                        session,
                        &order
                            .to_bytes()
                            .map_err(security(ErrorCode::InvalidInput))?,
                    )?
                {
                    return Ok(staged);
                }
            }
            return Ok(json!({"state":"membership_branch_kept"}));
        }
        BranchDecision::Orphaned(branch) => (
            owner
                .provisional_copy()
                .map_err(security(ErrorCode::StorageCorrupt))?,
            branch,
            session.delivery.publisher.clone(),
            session.delivery.inbox.clone(),
            session.membership.fork.carried.clone(),
        ),
        BranchDecision::Switch(prepared) => {
            let key = session
                .storage_key
                .as_ref()
                .ok_or_else(errors::no_root_key)?;
            let mut at_fork = Workspace::restore_branch_snapshot(
                key,
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
            let next = match prepare_step(&at_fork, &authorization, &commit)
                .map_err(security(ErrorCode::InvalidInput))?
            {
                PreparedManagementUpdate::Active(next) => *next,
                PreparedManagementUpdate::Removed(removed) => {
                    return serde_json::to_value(stage_removal(session, removed)?)
                        .map_err(errors::encode);
                }
            };
            let mut orders = Vec::new();
            let mut lost = session.membership.fork.carried.clone();
            for previous in epoch..owner.epoch() {
                if let Some((MembershipAuthorization::Revocation(order), _)) = owner
                    .history_step(previous)
                    .map_err(security(ErrorCode::StorageCorrupt))?
                {
                    lost.push(order);
                }
            }
            for order in lost {
                match next.rebase_revocation(&order, owner, &at_fork) {
                    Ok(order) => retain_order(&next, &mut orders, order)?,
                    Err(reason) => eprintln!("arachne: losing revocation discarded: {reason}"),
                }
            }
            if let (Some(publisher), Some(inbox)) =
                (&session.delivery.publisher, &session.delivery.inbox)
            {
                for publication in inbox
                    .own_losing_publications(owner, publisher, epoch)
                    .map_err(crate::errors::delivery(ErrorCode::StorageCorrupt))?
                {
                    if republications
                        .iter()
                        .any(|pending| pending.id == publication.context.id)
                    {
                        continue;
                    }
                    republications.push(StagePublicationArgs {
                        workspace: Some(publication.context.workspace),
                        revision: publication.context.revision,
                        topic: publication.context.topic.as_str().to_owned(),
                        id: publication.context.id,
                        payload: publication.payload,
                        recipients: publication.recipients,
                        bulk: false,
                        current: publication.current.map(|current| CurrentPublication {
                            selector: current.selector,
                            replacement_key: current.replacement_key,
                            expires_at: current.expires_at,
                            tombstone: current.tombstone,
                        }),
                    });
                }
                encode_republications(&republications)?;
            }
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
            (next, prepared.into_parts().1, publisher, inbox, orders)
        }
    };
    let orphaned = branch.is_orphaned();
    let snapshot = seal_state(
        session.records.is_some(),
        &next,
        session
            .storage_key
            .as_ref()
            .ok_or_else(errors::no_root_key)?,
        publisher.as_ref(),
        inbox.as_ref(),
    )?;
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
    session.membership.fork.candidate = Some(BranchCandidate {
        token: snapshot.clone(),
        branch,
        orders,
        republications,
    });
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

fn prepare_step(
    owner: &Workspace,
    authorization: &MembershipAuthorization,
    commit: &[u8],
) -> Result<PreparedManagementUpdate, &'static str> {
    Ok(match authorization {
        MembershipAuthorization::Admission(auth) => PreparedManagementUpdate::Active(Box::new(
            owner.prepare_admission_update(auth, commit)?,
        )),
        MembershipAuthorization::AdmissionBatch(auths) => PreparedManagementUpdate::Active(
            Box::new(owner.prepare_admission_batch_update(auths, commit)?),
        ),
        _ => owner.prepare_step_update(authorization, commit)?,
    })
}

fn retain_order(
    owner: &Workspace,
    orders: &mut Vec<OrderStep>,
    order: OrderStep,
) -> Result<(), ApiError> {
    if orders
        .iter()
        .any(|old| old.order.digest() == order.order.digest())
    {
        return Ok(());
    }
    if order.order.kind.removes()
        && !owner
            .member_roster()
            .map_err(security(ErrorCode::StorageCorrupt))?
            .iter()
            .any(|member| member.id == order.order.target)
    {
        return Ok(());
    }
    if orders.len() == MAX_CARRIED_ORDERS
        || order
            .to_bytes()
            .map_err(security(ErrorCode::InvalidInput))?
            .len()
            > MAX_WIRE_STEP
    {
        return Err(ApiError::invalid_input(
            "order",
            "carried revocation exceeds runtime bounds",
        ));
    }
    orders.push(order);
    orders.sort_by_key(|step| step.order.digest());
    Ok(())
}

/// Commit one carried order. Receiving remains available during quarantine.
pub(crate) fn stage_carried(session: &mut Session) -> Result<Option<Value>, ApiError> {
    if session.transition.staged.is_some() || session.transition.removal.is_some() {
        return Ok(None);
    }
    require_active_branch(session)?;
    let Some(owner) = &session.workspace else {
        return Ok(None);
    };
    let own_id = owner.member().ok_or_else(errors::no_workspace)?.id();
    let Some(order) = session
        .membership
        .fork
        .carried
        .iter()
        .find(|order| !(order.order.kind.removes() && order.order.target == own_id))
        .cloned()
    else {
        return Ok(None);
    };
    let prepared = match owner.prepare_revocation(&order) {
        Ok(prepared) => prepared,
        Err(reason) => {
            let orders = session
                .membership
                .fork
                .carried
                .iter()
                .filter(|pending| pending.order.digest() != order.order.digest())
                .cloned()
                .collect();
            let mut value = stage_orders(session, orders, "carried_revocation_discarded")?;
            value["reason"] = json!(reason);
            return Ok(Some(value));
        }
    };
    let value = stage_prepared(session, prepared)?;
    let mut value = serde_json::to_value(value).map_err(errors::encode)?;
    value["carried_revocation"] = json!(order.order.digest());
    Ok(Some(value))
}

pub(crate) fn stage_republication(session: &mut Session) -> Result<Option<Value>, ApiError> {
    if session.transition.staged.is_some()
        || session.transition.removal.is_some()
        || !has_republication_work(session)
    {
        return Ok(None);
    }
    let mut publication = session.membership.fork.republications[0].clone();
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    if let Some(revision) = session.runtime.block_on(
        session
            .node
            .with_routing_policy(|routing| routing.installed_revision(owner.id())),
    ) {
        publication.revision = revision;
    }
    let direct = !publication.recipients.is_empty();
    publication
        .recipients
        .retain(|member| owner.endpoints_for_members(&[*member]).is_ok());
    let expired = publication.current.is_some_and(|current| {
        arachne_delivery::UnixSeconds::now()
            .is_ok_and(|now| !now.before_local_expiry(current.expires_at))
    });
    if (direct && publication.recipients.is_empty()) || expired {
        let orders = session.membership.fork.carried.clone();
        let mut value = stage_orders(session, orders, "republication_discarded")?;
        value["reason"] = json!(if expired {
            "expired"
        } else {
            "no_remaining_recipient"
        });
        session
            .membership
            .fork
            .candidate
            .as_mut()
            .unwrap()
            .republications
            .remove(0);
        return Ok(Some(value));
    }
    let staged = crate::ops::publication::stage_republication(session, publication)?;
    let mut value = serde_json::to_value(staged).map_err(errors::encode)?;
    value["republication"] = json!(true);
    Ok(Some(value))
}

pub(crate) fn announce_orders(session: &Session) {
    let Some(owner) = &session.workspace else {
        return;
    };
    for order in &session.membership.fork.carried {
        let Ok(bytes) = order.to_bytes() else {
            continue;
        };
        let mut payload = GOSSIP_ORDER.to_vec();
        payload.extend(owner.id());
        payload.extend(bytes);
        let send = session.node.broadcast_membership(owner.id(), payload);
        session.runtime.spawn(async move {
            let _ = send.await;
        });
    }
}

/// A signed order can arrive from any relay. Verification binds its anchor
/// and winning path to this workspace before it can quarantine transmission.
pub(crate) fn receive_order(
    session: &mut Session,
    bytes: &[u8],
) -> Result<Option<Value>, ApiError> {
    if bytes.len() > MAX_WIRE_STEP || session.transition.staged.is_some() {
        return Ok(None);
    }
    let Some(owner) = &session.workspace else {
        return Ok(None);
    };
    let Ok(order) = OrderStep::from_bytes(bytes).and_then(|step| owner.extend_revocation(&step))
    else {
        return Ok(None);
    };
    let mut orders = session.membership.fork.carried.clone();
    let count = orders.len();
    retain_order(owner, &mut orders, order)?;
    if orders.len() == count {
        return Ok(None);
    }
    stage_orders(session, orders, "carried_revocation_received").map(Some)
}

fn stage_orders(
    session: &mut Session,
    orders: Vec<OrderStep>,
    state: &'static str,
) -> Result<Value, ApiError> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let next = owner
        .provisional_copy()
        .map_err(security(ErrorCode::StorageCorrupt))?;
    let publisher = session.delivery.publisher.clone();
    let inbox = session.delivery.inbox.clone();
    let snapshot = seal_state(
        session.records.is_some(),
        &next,
        session
            .storage_key
            .as_ref()
            .ok_or_else(errors::no_root_key)?,
        publisher.as_ref(),
        inbox.as_ref(),
    )?;
    let branch = session
        .membership
        .fork
        .retained
        .clone()
        .unwrap_or_else(|| BranchState::new(owner.epoch()));
    let mut value = serde_json::to_value(StagedCandidate::new(
        next.id(),
        next.workspace_name()
            .map_err(security(ErrorCode::StorageCorrupt))?,
        snapshot.clone(),
    ))
    .map_err(errors::encode)?;
    value["branch_state"] = json!(state);
    session.membership.fork.candidate = Some(BranchCandidate {
        token: snapshot.clone(),
        branch,
        orders,
        republications: session.membership.fork.republications.clone(),
    });
    session.transition.staged = Some(StagedWorkspace {
        publisher,
        inbox,
        transition: WorkspaceTransition::Admission,
        workspace: next,
        snapshot,
    });
    session.membership.staged_step_received = true;
    Ok(value)
}

/// Serve only the public steps this authenticated peer may already read.
pub(crate) fn reply(owner: Option<&Workspace>, peer: [u8; 32], bytes: &[u8]) -> Vec<u8> {
    let build = || -> Result<Vec<u8>, ApiError> {
        let owner = owner.ok_or_else(errors::no_workspace)?;
        let query = wire::decode_branch_query(bytes)
            .map_err(|reason| ApiError::invalid_input("branch", reason))?;
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
                let bytes = wire::encode_range_query(&query)
                    .map_err(|reason| ApiError::invalid_input("branch", reason))?;
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
