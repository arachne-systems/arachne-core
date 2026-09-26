//! Native persistence owns secrets; callers exchange only candidate tokens.
use super::*;
use crate::errors::{self, delivery, security};
use crate::ops::candidate::Removed;
use crate::ops::join::PendingJoinInfo;
use crate::ops::workspace::WorkspaceOpened;
use arachne_api::{ApiError, ErrorCode};
use arachne_security::{SecurityRecords, Workspace};
use arachne_store::{FreshnessAnchor, Store};
use std::path::Path;
use zeroize::Zeroizing;

const TOKEN: &[u8] = b"runtime/token";
const PENDING: &[u8] = b"runtime/pending";
const JOIN_LIFECYCLE: &[u8] = b"runtime/join-lifecycle";
const ACTIVITY: &[u8] = b"runtime/activity";
const RESET: &[u8] = b"runtime/reset";
const REMOVED: &[u8] = b"runtime/removed";
const INBOX: &[u8] = b"delivery/inbox";

pub(super) struct NativeStore {
    store: Store,
    committed: Vec<u8>,
}
impl NativeStore {
    pub(super) fn require_committed(&self, token: &[u8]) -> Result<(), ApiError> {
        if token != self.committed {
            return Err(ApiError::wrong_state(
                "candidate has not been committed to native storage",
            ));
        }
        Ok(())
    }
    fn commit(&mut self, mut records: SecurityRecords, token: &[u8]) -> Result<(), ApiError> {
        records.insert(TOKEN.to_vec(), Zeroizing::new(token.to_vec()));
        let deleted: Vec<_> = self
            .store
            .keys(b"")
            .filter(|name| !records.contains_key(*name))
            .map(<[u8]>::to_vec)
            .collect();
        let mut changes = Vec::new();
        for (name, value) in &records {
            if self.store.get(name).map_err(errors::store)?.as_deref() != Some(value.as_ref()) {
                changes.push((name.as_slice(), Some(value.as_slice())));
            }
        }
        changes.extend(deleted.iter().map(|name| (name.as_slice(), None)));
        self.store
            .commit(self.store.revision(), &changes)
            .map_err(errors::store)?;
        self.committed = token.to_vec();
        Ok(())
    }
}

/// A restored session: a pending join, this member's removal (the session
/// then ends), or an active workspace.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(untagged)]
pub(crate) enum Restored {
    Pending(PendingJoinInfo),
    Removed(RemovedDurably),
    Opened(WorkspaceOpened),
}

/// A durable removal: `Removed` plus `durable: true`.
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct RemovedDurably {
    #[serde(flatten)]
    pub removed: Removed,
    pub durable: bool,
}

pub(super) fn candidate_token() -> Result<Vec<u8>, ApiError> {
    let mut token = vec![0; 37];
    token[..5].copy_from_slice(b"DFRC\x01");
    getrandom::fill(&mut token[5..]).map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(token)
}

fn encode_activity(activity: &WorkspaceActivity) -> Result<Vec<u8>, ApiError> {
    serde_json::to_vec(activity).map_err(errors::encode)
}

fn decode_activity(bytes: &[u8]) -> Result<WorkspaceActivity, ApiError> {
    serde_json::from_slice::<WorkspaceActivity>(bytes)
        .map_err(|error| ApiError::storage_corrupt(error.to_string()))
}

fn active_records(
    owner: &Workspace,
    publisher: Option<&arachne_delivery::PublisherLog>,
    inbox: Option<&arachne_delivery::inbox::ObjectInbox>,
    activity: &WorkspaceActivity,
) -> Result<SecurityRecords, ApiError> {
    let mut records = owner
        .export_records()
        .map_err(security(ErrorCode::StorageFailed))?;
    records.insert(ACTIVITY.to_vec(), Zeroizing::new(encode_activity(activity)?));
    match (inbox, publisher) {
        (Some(inbox), Some(publisher)) => {
            records.insert(
                INBOX.to_vec(),
                Zeroizing::new(
                    inbox
                        .snapshot_with_publisher(owner, publisher)
                        .map_err(delivery(ErrorCode::StorageFailed))?,
                ),
            );
        }
        (None, None) => {}
        _ => {
            return Err(ApiError::internal(
                "object inbox and publisher state go together",
            ));
        }
    }
    Ok(records)
}

fn root_required() -> ApiError {
    ApiError::wrong_state("protected root required")
}

fn not_enabled() -> ApiError {
    ApiError::wrong_state("native record storage not enabled")
}

fn pending_records(
    session: &Session,
    pending: &arachne_security::PendingJoin,
) -> Result<SecurityRecords, ApiError> {
    let bytes = pending
        .seal(session.storage_key.as_ref().ok_or_else(root_required)?)
        .map_err(security(ErrorCode::StorageFailed))?;
    let mut records = BTreeMap::from([(PENDING.to_vec(), Zeroizing::new(bytes))]);
    if let Some(lifecycle) = &session.join.lifecycle {
        records.insert(
            JOIN_LIFECYCLE.to_vec(),
            Zeroizing::new(serde_json::to_vec(lifecycle).map_err(errors::encode)?),
        );
    }
    records.insert(
        ACTIVITY.to_vec(),
        Zeroizing::new(encode_activity(&session.activity)?),
    );
    Ok(records)
}

fn idle(session: &Session) -> Result<(), ApiError> {
    if session.records.is_some()
        || session.transition.staged.is_some()
        || session.transition.removal.is_some()
        || session.transition.inbound.is_some()
        || session.membership.update.is_some()
        || session.recovery.cutoff.is_some()
        || session.recovery.current_view.is_some()
        || session.recovery.ready_current_view.is_some()
        || session.recovery.range.is_some()
        || session.recovery.ready_range.is_some()
    {
        return Err(ApiError::wrong_state(
            "record storage requires an idle session",
        ));
    }
    Ok(())
}

/// Run `body` on the live session under its lock. The persistence calls do
/// not pass the op guards, as before; a body that ends the session (a
/// restored removal) sets `ending`, and the session is then shut down
/// outside the lock.
pub(crate) fn with_session<T>(
    handle: i64,
    body: impl FnOnce(&mut Session) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let shared = session(handle)?;
    let mut guard = shared
        .lock()
        .map_err(errors::poisoned("node session unavailable"))?;
    let session = guard.as_mut().ok_or_else(errors::closed)?;
    let result = body(session)?;
    if session.ending {
        let ended = guard.take().ok_or_else(errors::closed)?;
        drop(guard);
        shutdown_session(ended)?;
    }
    Ok(result)
}

/// Atomically migrate the current accepted owner and delivery state into an empty
/// record store. The host supplies a private path and protected storage root and
/// must retain its endpoint credential lock. Existing stores require restore;
/// never overwrite one with an older legacy snapshot or fall back on open failure.
/// A pending join may migrate too; admission atomically replaces its records.
/// Host route/unknown-outcome metadata remains separate and must be preserved.
pub fn enable_record_storage(handle: i64, path: &Path, root: &[u8; 32]) -> Result<(), String> {
    with_session(handle, |session| enable(session, path, root)).map_err(errors::text)
}

pub(crate) fn enable(session: &mut Session, path: &Path, root: &[u8; 32]) -> Result<(), ApiError> {
    idle(session)?;
    if session.storage_key.is_none() {
        return Err(ApiError::wrong_state("protected endpoint root required"));
    }
    let (workspace, mut records) = if let Some(owner) = &session.workspace {
        (
            owner.id(),
            active_records(
                owner,
                session.delivery.publisher.as_ref(),
                session.delivery.inbox.as_ref(),
                &session.activity,
            )?,
        )
    } else if let Some(pending) = &session.join.pending {
        (pending.workspace_id(), pending_records(session, pending)?)
    } else {
        return Err(ApiError::wrong_state(
            "session has no workspace or pending join",
        ));
    };
    records.extend(membership::fork::records(session, false)?);
    let store = Store::open(path, root, workspace).map_err(errors::store)?;
    if store.revision() != 0 {
        return Err(ApiError::wrong_state(
            "record store already initialized; restore it",
        ));
    }
    let mut native = NativeStore {
        store,
        committed: Vec::new(),
    };
    native.commit(records, &candidate_token()?)?;
    session.records = Some(native);
    Ok(())
}

/// Commit the exact staged candidate, including counters and delivery state.
/// This does not adopt, send, reply or release application data. Retry after a
/// successful commit is idempotent; callers still invoke the matching adoption.
pub fn save_candidate(handle: i64, token: &[u8]) -> Result<(), String> {
    with_session(handle, |session| commit_candidate(session, token)).map_err(errors::text)
}

/// Commit the exact staged candidate using the native store already attached to
/// this session. The lifecycle driver calls this before adoption, so Android
/// never becomes the authority for the save/adopt ordering.
pub(super) fn commit_candidate(session: &mut Session, token: &[u8]) -> Result<(), ApiError> {
    membership::fork::prepare_candidate(session)?;
    let mut records = if let Some(staged) = &session.transition.staged {
        if token != staged.snapshot {
            return Err(ApiError::candidate_stale("token does not match candidate"));
        }
        let activity = if matches!(staged.transition, WorkspaceTransition::Join) {
            WorkspaceActivity {
                phase: WorkspacePhase::Active,
                reason: None,
            }
        } else {
            session.activity.clone()
        };
        active_records(
            &staged.workspace,
            staged.publisher.as_ref(),
            staged.inbox.as_ref(),
            &activity,
        )?
    } else if let Some((removed, expected)) = &session.transition.removal {
        if token != expected {
            return Err(ApiError::candidate_stale("token does not match removal"));
        }
        let bytes = removed
            .seal(session.storage_key.as_ref().ok_or_else(root_required)?)
            .map_err(security(ErrorCode::StorageFailed))?;
        BTreeMap::from([(REMOVED.to_vec(), Zeroizing::new(bytes))])
    } else {
        return Err(ApiError::wrong_state("session has no candidate"));
    };
    if session.transition.staged.is_some() {
        records.extend(membership::fork::records(session, true)?);
    }
    let store = session.records.as_mut().ok_or_else(not_enabled)?;
    if store.require_committed(token).is_ok() {
        return Ok(());
    }
    store.commit(records, token)
}

/// Persist pending join routing before an Iroh admission exchange can leave the
/// endpoint. This makes an interrupted send retry the same attempt/peer.
pub(super) fn commit_pending_join(session: &mut Session) -> Result<(), ApiError> {
    let pending = session
        .join
        .pending
        .as_ref()
        .ok_or_else(errors::no_pending_join)?;
    let records = pending_records(session, pending)?;
    let token = candidate_token()?;
    session
        .records
        .as_mut()
        .ok_or_else(not_enabled)?
        .commit(records, &token)
}

/// Replace the native record set with an invalidation marker. The marker is
/// deliberately not restorable as a workspace; an adapter may then remove the
/// directory, but a crash between reset and cleanup cannot resurrect old state.
pub(super) fn reset_records(
    session: &mut Session,
    activity: &WorkspaceActivity,
) -> Result<(), ApiError> {
    let records = BTreeMap::from([
        (
            RESET.to_vec(),
            Zeroizing::new(vec![b'D', b'F', b'R', b'S', 1]),
        ),
        (ACTIVITY.to_vec(), Zeroizing::new(encode_activity(activity)?)),
    ]);
    let token = candidate_token()?;
    session
        .records
        .as_mut()
        .ok_or_else(not_enabled)?
        .commit(records, &token)
}

/// Freshness anchor of the attached native store after its latest commit.
/// Commits also happen inside `execute` operations, so while record storage is
/// enabled read this after every call and persist it outside the database
/// before releasing that call's result.
pub fn record_freshness(handle: i64) -> Result<FreshnessAnchor, String> {
    with_session(handle, |session| freshness(session)).map_err(errors::text)
}

pub(crate) fn freshness(session: &mut Session) -> Result<FreshnessAnchor, ApiError> {
    Ok(session
        .records
        .as_ref()
        .ok_or_else(not_enabled)?
        .store
        .freshness())
}

/// Restore only the authoritative native store into an empty endpoint session.
/// Failure must not trigger legacy fallback. Removal consumes the session.
/// Without an anchor this cannot detect a whole-database rollback; prefer
/// `restore_record_storage_with_freshness`.
pub fn restore_record_storage(
    handle: i64,
    path: &Path,
    root: &[u8; 32],
    workspace: [u8; 32],
) -> Result<Value, String> {
    restore_record_storage_with_freshness(handle, path, root, workspace, None)
}

/// Restore as `restore_record_storage`, first requiring the store to match the
/// last anchor the host saved from `record_freshness`. Any difference, older or
/// newer, is rejected before any record is read and leaves the session empty.
pub fn restore_record_storage_with_freshness(
    handle: i64,
    path: &Path,
    root: &[u8; 32],
    workspace: [u8; 32],
    expected: Option<FreshnessAnchor>,
) -> Result<Value, String> {
    with_session(handle, |session| {
        let restored = restore(session, path, root, workspace, expected)?;
        serde_json::to_value(restored).map_err(errors::encode)
    })
    .map_err(errors::text)
}

pub(crate) fn restore(
    session: &mut Session,
    path: &Path,
    root: &[u8; 32],
    workspace: [u8; 32],
    expected: Option<FreshnessAnchor>,
) -> Result<Restored, ApiError> {
    idle(session)?;
    if session.workspace.is_some() || session.join.pending.is_some() {
        return Err(ApiError::wrong_state("session already owns a workspace"));
    }
    // An absent authoritative store must never become a new empty database.
    std::fs::metadata(path).map_err(errors::store)?;
    let store = Store::open(path, root, workspace).map_err(errors::store)?;
    // Before any record is read: a rolled-back store would replay MLS state
    // and reuse sender counters (AES-GCM nonces).
    if let Some(expected) = expected {
        store
            .verify_freshness(expected)
            .map_err(|error| ApiError::candidate_stale(error.to_string()))?;
    }
    let get = |name: &[u8]| store.get(name).map_err(errors::store);
    let corrupt = |detail: &str| ApiError::storage_corrupt(detail);
    let committed = get(TOKEN)?
        .ok_or_else(|| corrupt("missing native commit token"))?
        .to_vec();
    if committed.len() != 37 || !committed.starts_with(b"DFRC\x01") {
        return Err(corrupt("invalid native commit token"));
    }
    if get(RESET)?.is_some() {
        return Err(ApiError::wrong_state("native record store was reset"));
    }
    if let Some(bytes) = get(PENDING)? {
        if store.keys(b"").any(|name| {
            name != PENDING && name != TOKEN && name != JOIN_LIFECYCLE && name != ACTIVITY
        }) {
            return Err(corrupt("pending store contains other lifecycle state"));
        }
        let pending = arachne_security::PendingJoin::restore(
            session.storage_key.as_ref().ok_or_else(root_required)?,
            session.node.id(),
            workspace,
            &bytes,
        )
        .map_err(security(ErrorCode::StorageCorrupt))?;
        let mut value = pending_metadata(&pending, session.node.id())?;
        value.durable = true;
        let activity = get(ACTIVITY)?
            .map(|bytes| decode_activity(&bytes))
            .transpose()?
            .unwrap_or(WorkspaceActivity {
                phase: WorkspacePhase::Joining,
                reason: None,
            });
        if activity.phase != WorkspacePhase::Joining {
            return Err(corrupt("pending store has invalid workspace activity"));
        }
        value.activity = Some(activity.view());
        session.activity = activity;
        session.join.lifecycle = get(JOIN_LIFECYCLE)?
            .map(|bytes| {
                let lifecycle: JoinLifecycle = serde_json::from_slice(&bytes)
                    .map_err(|error| ApiError::storage_corrupt(error.to_string()))?;
                lifecycle.validate()?;
                Ok::<JoinLifecycle, ApiError>(lifecycle)
            })
            .transpose()?;
        session.join.pending = Some(pending);
        session.records = Some(NativeStore { store, committed });
        return Ok(Restored::Pending(value));
    }
    if let Some(bytes) = get(REMOVED)? {
        if store.keys(b"").count() != 2 {
            return Err(corrupt("removed store contains active state"));
        }
        let removed = arachne_security::RemovedMembership::restore(
            session.storage_key.as_ref().ok_or_else(root_required)?,
            session.node.id(),
            workspace,
            &bytes,
        )
        .map_err(security(ErrorCode::StorageCorrupt))?;
        let mut value = Removed::of(&removed);
        value.workspace = workspace;
        session.ending = true;
        return Ok(Restored::Removed(RemovedDurably {
            removed: value,
            durable: true,
        }));
    }
    for name in store.keys(b"") {
        if !name.starts_with(b"security/") && !name.starts_with(membership::fork::PREFIX)
            && ![TOKEN, INBOX, ACTIVITY].contains(&name) {
            return Err(corrupt("unknown native runtime record"));
        }
    }
    let security_records: SecurityRecords = store
        .keys(b"security/")
        .map(|name| {
            Ok((
                name.to_vec(),
                get(name)?.ok_or_else(|| corrupt("missing security record"))?,
            ))
        })
        .collect::<Result<_, ApiError>>()?;
    let owner = Workspace::restore_records(session.node.id(), workspace, &security_records)
        .map_err(security(ErrorCode::StorageCorrupt))?;
    let (publisher, inbox) = match get(INBOX)? {
        Some(bytes) => {
            let (publisher, inbox) =
                arachne_delivery::inbox::ObjectInbox::restore_snapshot(&owner, &bytes)
                    .map_err(delivery(ErrorCode::StorageCorrupt))?;
            (Some(publisher), Some(inbox))
        }
        None => (None, None),
    };
    let mut value = WorkspaceOpened::of(&owner, None, true)?;
    value.workspace = workspace;
    let activity = get(ACTIVITY)?
        .map(|bytes| decode_activity(&bytes))
        .transpose()?
        .unwrap_or(WorkspaceActivity {
            phase: WorkspacePhase::Active,
            reason: None,
        });
    if !matches!(activity.phase, WorkspacePhase::Active | WorkspacePhase::Recovering) {
        return Err(corrupt("active store has invalid workspace activity"));
    }
    let branch_records = store.keys(membership::fork::PREFIX).map(|name| {
        Ok((name.to_vec(), get(name)?.ok_or_else(|| corrupt("missing branch record"))?))
    }).collect::<Result<SecurityRecords, ApiError>>()?;
    membership::fork::restore(session, &branch_records)?;
    value.activity = activity.view();
    session.activity = activity;
    session.delivery.publisher = publisher;
    session.delivery.inbox = inbox;
    commit_workspace(session, owner);
    session.records = Some(NativeStore { store, committed });
    Ok(Restored::Opened(value))
}
