//! Native record storage: the one persistence mode (A5).
//!
//! The host attaches a [`StorageConfig`] to a session. Every accepted state
//! goes into the workspace's record store before it becomes live: core saves
//! the staged candidate, reads it back, and only then adopts it. The host
//! never sees state bytes; a candidate is an opaque token.
use super::*;
use crate::errors::{self, delivery, security};
use crate::ops::candidate::Removed;
use crate::ops::join::PendingJoinInfo;
use crate::ops::workspace::WorkspaceOpened;
use arachne_api::{ApiError, ErrorCode};
use arachne_security::{SecurityRecords, Workspace};
use arachne_store::{FreshnessAnchor, MemoryProvider, SqliteProvider, Storage, StorageProvider};
use std::path::Path;
use zeroize::Zeroizing;

const TOKEN: &[u8] = b"runtime/token";
const PENDING: &[u8] = b"runtime/pending";
const JOIN_LIFECYCLE: &[u8] = b"runtime/join-lifecycle";
const ACTIVITY: &[u8] = b"runtime/activity";
const RESET: &[u8] = b"runtime/reset";
const REMOVED: &[u8] = b"runtime/removed";
const INBOX: &[u8] = b"delivery/inbox";

// A pending join, with its checkpoint, is one record.
const _: () = assert!(arachne_security::MAX_SEALED_PENDING_JOIN <= arachne_store::MAX_RECORD_BYTES);

/// Where a session keeps its workspace records. One store per workspace.
#[derive(Clone)]
pub struct StorageConfig {
    provider: Arc<dyn StorageProvider>,
}

impl StorageConfig {
    pub fn new(provider: Arc<dyn StorageProvider>) -> Self {
        Self { provider }
    }

    /// Encrypted SQLite files in a private directory. `root` is the host's
    /// storage root key.
    pub fn sqlite(directory: &Path, root: [u8; 32]) -> Self {
        Self::new(Arc::new(SqliteProvider::new(directory, root)))
    }

    /// Process memory (tests). Clones of `provider` share the stores.
    pub fn memory(provider: &MemoryProvider) -> Self {
        Self::new(Arc::new(provider.clone()))
    }
}

impl std::fmt::Debug for StorageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageConfig").finish_non_exhaustive()
    }
}

impl PartialEq for StorageConfig {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.provider, &other.provider)
    }
}
impl Eq for StorageConfig {}

pub(crate) struct NativeStore {
    store: Box<dyn Storage>,
    committed: Vec<u8>,
    /// A commit failed or did not read back. The durable outcome is unknown,
    /// so live state must not advance: only close (then restore) or reset.
    pub(crate) uncertain: bool,
}

impl NativeStore {
    fn new(store: Box<dyn Storage>, committed: Vec<u8>) -> Self {
        Self {
            store,
            committed,
            uncertain: false,
        }
    }

    pub(crate) fn is_committed(&self, token: &[u8]) -> bool {
        !self.uncertain && token == self.committed
    }

    /// Save `records` as the complete record set, then read every record back.
    fn commit(&mut self, mut records: SecurityRecords, token: &[u8]) -> Result<(), ApiError> {
        if self.uncertain {
            return Err(uncertain());
        }
        records.insert(TOKEN.to_vec(), Zeroizing::new(token.to_vec()));
        let deleted: Vec<Vec<u8>> = self
            .store
            .keys(b"")
            .into_iter()
            .filter(|name| !records.contains_key(name))
            .collect();
        let mut changes = Vec::new();
        for (name, value) in &records {
            if self.store.get(name).map_err(errors::store)?.as_deref() != Some(value.as_ref()) {
                changes.push((name.as_slice(), Some(value.as_slice())));
            }
        }
        changes.extend(deleted.iter().map(|name| (name.as_slice(), None)));
        let revision = self.store.revision();
        if let Err(error) = self.store.commit(revision, &changes) {
            self.uncertain = true;
            return Err(errors::store(error));
        }
        if let Err(error) = self.read_back(&records) {
            self.uncertain = true;
            return Err(error);
        }
        self.committed = token.to_vec();
        Ok(())
    }

    fn read_back(&self, records: &SecurityRecords) -> Result<(), ApiError> {
        let keys = self.store.keys(b"");
        if keys.len() != records.len() || keys.iter().any(|name| !records.contains_key(name)) {
            return Err(ApiError::storage_failed("record set did not read back"));
        }
        for (name, value) in records {
            let stored = self.store.get(name).map_err(errors::store)?;
            if stored.as_deref() != Some(value.as_ref()) {
                return Err(ApiError::storage_failed("record did not read back"));
            }
        }
        Ok(())
    }

    fn terminal(&self) -> Result<bool, ApiError> {
        Ok(self.store.get(RESET).map_err(errors::store)?.is_some()
            || self.store.get(REMOVED).map_err(errors::store)?.is_some())
    }
}

fn uncertain() -> ApiError {
    ApiError::storage_failed("record storage outcome is uncertain; close and restore")
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

pub(crate) fn storage_required() -> ApiError {
    ApiError::wrong_state("record storage required; attach storage to the session")
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

/// Run `body` on the live session under its lock. The persistence calls do
/// not pass the op guards; a body that ends the session (a restored
/// removal) sets `ending`, and the session is then shut down outside the lock.
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

/// Attach record storage to a session that holds no workspace yet. Every
/// workspace op needs it: without storage a session cannot hold a workspace.
pub fn attach_storage(handle: i64, storage: StorageConfig) -> Result<(), String> {
    with_session(handle, |session| attach(session, storage)).map_err(errors::text)
}

pub(crate) fn attach(session: &mut Session, storage: StorageConfig) -> Result<(), ApiError> {
    if session.workspace.is_some() || session.join.pending.is_some() || session.records.is_some() {
        return Err(ApiError::wrong_state("session already owns a workspace"));
    }
    session.storage = Some(storage);
    Ok(())
}

/// Open the store of a new workspace or pending join. A store that exists
/// must be restored, unless it only holds a reset or removal marker.
fn open_new(session: &Session, workspace: [u8; 32]) -> Result<NativeStore, ApiError> {
    if session.records.is_some() {
        return Err(ApiError::wrong_state("session already owns a record store"));
    }
    let provider = &session.storage.as_ref().ok_or_else(storage_required)?.provider;
    if let Some(store) = provider.open(workspace).map_err(errors::store)? {
        let store = NativeStore::new(store, Vec::new());
        if !store.terminal()? {
            return Err(ApiError::wrong_state(
                "record store already initialized; restore it",
            ));
        }
        return Ok(store);
    }
    Ok(NativeStore::new(
        provider.create(workspace).map_err(errors::store)?,
        Vec::new(),
    ))
}

/// Save a newly created workspace before it becomes the committed one.
pub(crate) fn commit_created(
    session: &mut Session,
    owner: &Workspace,
    publisher: Option<&arachne_delivery::PublisherLog>,
    inbox: Option<&arachne_delivery::inbox::ObjectInbox>,
) -> Result<(), ApiError> {
    let mut store = open_new(session, owner.id())?;
    let activity = WorkspaceActivity {
        phase: WorkspacePhase::Active,
        reason: None,
    };
    store.commit(
        active_records(owner, publisher, inbox, &activity)?,
        &candidate_token()?,
    )?;
    session.records = Some(store);
    Ok(())
}

/// Save a new pending join (already set on the session) in a new store.
pub(crate) fn commit_begun_join(session: &mut Session) -> Result<(), ApiError> {
    let pending = session
        .join
        .pending
        .as_ref()
        .ok_or_else(errors::no_pending_join)?;
    let mut store = open_new(session, pending.workspace_id())?;
    store.commit(pending_records(session, pending)?, &candidate_token()?)?;
    session.records = Some(store);
    Ok(())
}

/// Save the exact staged candidate and read it back. This does not adopt,
/// send, reply or release application data. A second call for the same
/// candidate does nothing.
pub(crate) fn commit_candidate(session: &mut Session, token: &[u8]) -> Result<(), ApiError> {
    let store = session.records.as_ref().ok_or_else(storage_required)?;
    if store.uncertain {
        return Err(uncertain());
    }
    if store.is_committed(token) {
        return Ok(());
    }
    let records = if let Some(staged) = &session.transition.staged {
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
    session
        .records
        .as_mut()
        .ok_or_else(storage_required)?
        .commit(records, token)
}

/// Whether the staged candidate `token` is already in storage. A candidate
/// in storage cannot be discarded: live state would then fork from it.
pub(crate) fn candidate_saved(session: &Session, token: &[u8]) -> bool {
    session
        .records
        .as_ref()
        .is_some_and(|store| store.is_committed(token))
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
        .ok_or_else(storage_required)?
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
    let store = session.records.as_mut().ok_or_else(storage_required)?;
    // A reset starts over: it may follow a commit with an unknown outcome.
    store.uncertain = false;
    store.commit(records, &token)
}

/// Freshness anchor of the attached store after its latest commit.
/// Commits also happen inside ops, so read this after every call and
/// persist it outside the database before releasing that call's result.
pub fn record_freshness(handle: i64) -> Result<FreshnessAnchor, String> {
    with_session(handle, |session| freshness(session)).map_err(errors::text)
}

pub(crate) fn freshness(session: &mut Session) -> Result<FreshnessAnchor, ApiError> {
    Ok(session
        .records
        .as_ref()
        .ok_or_else(storage_required)?
        .store
        .freshness())
}

/// Restore the stored workspace, pending join or removal into an empty
/// session. With `expected`, the store must match that anchor exactly before
/// any record is read. Removal consumes the session.
pub(crate) fn restore(
    session: &mut Session,
    workspace: [u8; 32],
    expected: Option<FreshnessAnchor>,
) -> Result<Restored, ApiError> {
    if session.workspace.is_some() || session.join.pending.is_some() || session.records.is_some() {
        return Err(ApiError::wrong_state("session already owns a workspace"));
    }
    let provider = &session.storage.as_ref().ok_or_else(storage_required)?.provider;
    // An absent store must never become a new empty one.
    let store = provider
        .open(workspace)
        .map_err(errors::store)?
        .ok_or_else(|| ApiError::storage_failed("no record store for this workspace"))?;
    // Before any record is read: a rolled-back store would replay MLS state
    // and reuse sender counters (AES-GCM nonces).
    if let Some(expected) = expected
        && store.freshness() != expected
    {
        return Err(ApiError::candidate_stale(
            "record store freshness anchor mismatch",
        ));
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
    let keys = store.keys(b"");
    if let Some(bytes) = get(PENDING)? {
        if keys.iter().any(|name| {
            ![PENDING, TOKEN, JOIN_LIFECYCLE, ACTIVITY].contains(&name.as_slice())
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
            .ok_or_else(|| corrupt("pending store has no workspace activity"))?;
        if activity.phase != WorkspacePhase::Joining {
            return Err(corrupt("pending store has invalid workspace activity"));
        }
        value.activity = Some(activity.view());
        let lifecycle = get(JOIN_LIFECYCLE)?
            .map(|bytes| {
                let lifecycle: JoinLifecycle = serde_json::from_slice(&bytes)
                    .map_err(|error| ApiError::storage_corrupt(error.to_string()))?;
                lifecycle.validate()?;
                Ok::<JoinLifecycle, ApiError>(lifecycle)
            })
            .transpose()?;
        session.activity = activity;
        session.join.lifecycle = lifecycle;
        session.join.pending = Some(pending);
        session.records = Some(NativeStore::new(store, committed));
        return Ok(Restored::Pending(value));
    }
    if let Some(bytes) = get(REMOVED)? {
        if keys.len() != 2 {
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
    for name in &keys {
        if !name.starts_with(b"security/") && ![TOKEN, INBOX, ACTIVITY].contains(&name.as_slice()) {
            return Err(corrupt("unknown native runtime record"));
        }
    }
    let security_records: SecurityRecords = keys
        .iter()
        .filter(|name| name.starts_with(b"security/"))
        .map(|name| {
            Ok((
                name.clone(),
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
    let missing = owner
        .workspace_name_missing_history()
        .map_err(security(ErrorCode::Internal))?;
    let mut value = WorkspaceOpened::of(&owner, Some(missing), true)?;
    value.workspace = workspace;
    let activity = get(ACTIVITY)?
        .map(|bytes| decode_activity(&bytes))
        .transpose()?
        .ok_or_else(|| corrupt("active store has no workspace activity"))?;
    if !matches!(activity.phase, WorkspacePhase::Active | WorkspacePhase::Recovering) {
        return Err(corrupt("active store has invalid workspace activity"));
    }
    session.activity = activity;
    session.delivery.publisher = publisher;
    session.delivery.inbox = inbox;
    commit_workspace(session, owner);
    value.activity = session.activity.view();
    session.records = Some(NativeStore::new(store, committed));
    Ok(Restored::Opened(value))
}

/// Test fixture: write `owner` (and its delivery state) into `provider` in
/// the runtime record layout, as if a session had created it. Tests use it
/// to build state outside the runtime and then restore it. Not an import
/// path: nothing on a session accepts state bytes.
#[doc(hidden)]
pub fn seed_workspace(
    provider: &dyn StorageProvider,
    owner: &Workspace,
    publisher: Option<&arachne_delivery::PublisherLog>,
    inbox: Option<&arachne_delivery::inbox::ObjectInbox>,
) -> Result<(), String> {
    let (publisher, inbox) = match (publisher, inbox, owner.member().is_some()) {
        (Some(publisher), Some(inbox), _) => (Some(publisher.clone()), Some(inbox.clone())),
        (None, None, true) => (
            Some(arachne_delivery::PublisherLog::new(owner)?),
            Some(arachne_delivery::inbox::ObjectInbox::new(
                owner.id(),
                owner.epoch(),
            )),
        ),
        _ => (None, None),
    };
    let activity = WorkspaceActivity {
        phase: WorkspacePhase::Active,
        reason: None,
    };
    let records = active_records(owner, publisher.as_ref(), inbox.as_ref(), &activity)
        .map_err(errors::text)?;
    let mut store = match provider.open(owner.id()).map_err(|e| e.to_string())? {
        Some(store) => store,
        None => provider.create(owner.id()).map_err(|e| e.to_string())?,
    };
    let mut store_records = records;
    store_records.insert(TOKEN.to_vec(), Zeroizing::new(candidate_token().map_err(errors::text)?));
    let stale: Vec<Vec<u8>> = store
        .keys(b"")
        .into_iter()
        .filter(|name| !store_records.contains_key(name))
        .collect();
    let mut changes: Vec<arachne_store::Change<'_>> = store_records
        .iter()
        .map(|(name, value)| (name.as_slice(), Some(value.as_slice())))
        .collect();
    changes.extend(stale.iter().map(|name| (name.as_slice(), None)));
    let revision = store.revision();
    store.commit(revision, &changes).map_err(|e| e.to_string())?;
    Ok(())
}
