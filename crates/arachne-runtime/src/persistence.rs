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
use arachne_store::{
    AnchorSlots, AnchorStore, FreshnessAnchor, MemoryProvider, SqliteProvider, Storage,
    StorageProvider,
};
use std::path::Path;
use zeroize::Zeroizing;

const TOKEN: &[u8] = b"runtime/token";
const PENDING: &[u8] = b"runtime/pending";
const JOIN_LIFECYCLE: &[u8] = b"runtime/join-lifecycle";
const ACTIVITY: &[u8] = b"runtime/activity";
const RESET: &[u8] = b"runtime/reset";
const REMOVED: &[u8] = b"runtime/removed";
const INBOX: &[u8] = b"delivery/inbox";
/// The endpoint key the stored state belongs to. Checked before any state
/// record is read, so a new endpoint identity gets a clear error.
const ENDPOINT: &[u8] = b"runtime/endpoint";
/// The runtime record format (big-endian u32), written with every commit.
const FORMAT: &[u8] = b"runtime/format";
/// The runtime record format this build reads and writes.
pub(crate) const RUNTIME_FORMAT: u32 = 1;
/// Upgrades one format to the next: `MIGRATIONS[n]` turns format `n + 1`
/// records into format `n + 2`. Empty: format 1 is the first, and there are
/// no legacy readers.
type Migration = fn(&mut SecurityRecords) -> Result<(), ApiError>;
const MIGRATIONS: &[Migration] = &[];
const _: () = assert!(MIGRATIONS.len() + 1 == RUNTIME_FORMAT as usize);

// A pending join, with its checkpoint, fits one part.
const _: () = assert!(arachne_security::MAX_SEALED_PENDING_JOIN <= arachne_store::MAX_RECORD_BYTES);

/// A value longer than this is saved as parts (A3g): the MLS ratchet tree of
/// a large roster is larger than the store's 1 MiB record limit.
const PART_BYTES: usize = 512 * 1024;
/// Stored value tags: the value itself, or the number of its parts.
const WHOLE: u8 = 0;
const PARTS: u8 = 1;
/// Parts of `name` are stored at `name`, this marker, and a u32 index.
/// Record names never contain a NUL byte.
const PART_MARKER: &[u8] = b"\x00part/";
const _: () = assert!(PART_BYTES < arachne_store::MAX_RECORD_BYTES);

fn is_part(name: &[u8]) -> bool {
    name.windows(PART_MARKER.len())
        .any(|window| window == PART_MARKER)
}

fn part_name(name: &[u8], index: u32) -> Vec<u8> {
    let mut part = name.to_vec();
    part.extend(PART_MARKER);
    part.extend(index.to_be_bytes());
    part
}

/// The stored form of `records`: each value tagged, long values in parts.
fn expand(records: &SecurityRecords) -> Result<SecurityRecords, ApiError> {
    let mut stored = SecurityRecords::new();
    for (name, value) in records {
        if is_part(name) {
            return Err(ApiError::storage_failed(
                "record name holds the part marker",
            ));
        }
        if value.len() <= PART_BYTES {
            let mut tagged = Zeroizing::new(Vec::with_capacity(value.len() + 1));
            tagged.push(WHOLE);
            tagged.extend_from_slice(value);
            stored.insert(name.clone(), tagged);
            continue;
        }
        let parts = value.chunks(PART_BYTES);
        let count = u32::try_from(parts.len())
            .map_err(|_| ApiError::storage_failed("record has too many parts"))?;
        let mut index = Zeroizing::new(vec![PARTS]);
        index.extend(count.to_be_bytes());
        stored.insert(name.clone(), index);
        for (number, part) in (0..count).zip(parts) {
            stored.insert(part_name(name, number), Zeroizing::new(part.to_vec()));
        }
    }
    Ok(stored)
}

/// The records of a store as the runtime wrote them: parts joined, tags removed.
struct Logical<'a> {
    store: &'a dyn Storage,
    legacy: bool,
}

impl Logical<'_> {
    fn keys(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.store
            .keys(prefix)
            .into_iter()
            .filter(|name| self.legacy || !is_part(name))
            .collect()
    }

    fn get(&self, name: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, ApiError> {
        let Some(stored) = self.store.get(name).map_err(errors::store)? else {
            return Ok(None);
        };
        if self.legacy {
            return Ok(Some(stored));
        }
        let corrupt = || ApiError::storage_corrupt("invalid stored record encoding");
        match stored.split_first() {
            Some((&WHOLE, value)) => Ok(Some(Zeroizing::new(value.to_vec()))),
            Some((&PARTS, count)) => {
                let count = u32::from_be_bytes(count.try_into().map_err(|_| corrupt())?);
                let mut value = Zeroizing::new(Vec::new());
                for number in 0..count {
                    let part = self
                        .store
                        .get(&part_name(name, number))
                        .map_err(errors::store)?
                        .ok_or_else(corrupt)?;
                    value.extend_from_slice(&part);
                }
                Ok(Some(value))
            }
            _ => Err(corrupt()),
        }
    }
}

impl<'a> Logical<'a> {
    fn current(store: &'a dyn Storage) -> Self {
        Self {
            store,
            legacy: false,
        }
    }

    fn legacy(store: &'a dyn Storage) -> Self {
        Self {
            store,
            legacy: true,
        }
    }
}

/// Where a session keeps its workspace records. One store per workspace.
///
/// `root` is the host's storage root key. It is not the endpoint secret:
/// a session without an endpoint secret can persist, and a new endpoint
/// identity does not change how the store is read.
///
/// With [`StorageConfig::with_anchors`] (monotonic host storage), core saves
/// the freshness anchor with every commit and restore requires a match: a
/// rolled-back database is refused. SQLite restore otherwise requires the
/// host to save `record_freshness` and pass it back explicitly.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct StorageConfig {
    provider: Arc<dyn StorageProvider>,
    root: Arc<Zeroizing<[u8; 32]>>,
    anchors: Option<Arc<dyn AnchorStore>>,
    requires_freshness: bool,
}

impl StorageConfig {
    pub fn new(provider: Arc<dyn StorageProvider>, root: [u8; 32]) -> Self {
        Self {
            provider,
            root: Arc::new(Zeroizing::new(root)),
            anchors: None,
            requires_freshness: false,
        }
    }

    /// Keep freshness anchors in the platform's monotonic storage. Restore
    /// then requires the saved anchor.
    pub fn with_anchors(mut self, anchors: Arc<dyn AnchorStore>) -> Self {
        self.anchors = Some(anchors);
        self
    }

    /// Encrypted SQLite files in a private directory, all under `root`.
    pub fn sqlite(directory: &Path, root: [u8; 32]) -> Self {
        let mut config = Self::new(Arc::new(SqliteProvider::new(directory, root)), root);
        config.requires_freshness = true;
        config
    }

    /// Process memory (tests). Clones of `provider` share the stores.
    pub fn memory(provider: &MemoryProvider) -> Self {
        Self::new(Arc::new(provider.clone()), provider.root())
    }

    /// The key that seals the pending join and removal records.
    fn record_key(&self) -> Result<arachne_security::StorageKey, ApiError> {
        arachne_security::StorageKey::derive(&self.root).map_err(security(ErrorCode::StorageFailed))
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
    scope: [u8; 32],
    anchors: Option<Arc<dyn AnchorStore>>,
    endpoint: [u8; 32],
    committed: Vec<u8>,
    /// A commit failed or did not read back. The durable outcome is unknown,
    /// so live state must not advance: only close (then restore) or reset.
    pub(crate) uncertain: bool,
}

impl NativeStore {
    fn new(
        store: Box<dyn Storage>,
        scope: [u8; 32],
        config: &StorageConfig,
        endpoint: [u8; 32],
        committed: Vec<u8>,
    ) -> Self {
        Self {
            store,
            scope,
            anchors: config.anchors.clone(),
            endpoint,
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
        records.insert(ENDPOINT.to_vec(), Zeroizing::new(self.endpoint.to_vec()));
        records.insert(
            FORMAT.to_vec(),
            Zeroizing::new(RUNTIME_FORMAT.to_be_bytes().to_vec()),
        );
        let records = expand(&records)?;
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
        let written: Vec<Vec<u8>> = changes
            .iter()
            .filter(|(_, value)| value.is_some())
            .map(|(name, _)| name.to_vec())
            .collect();
        let revision = self.store.revision();
        let current = self.store.freshness();
        let (scope, anchors) = (self.scope, self.anchors.clone());
        let committed = match &anchors {
            // Name the coming state first, so a crash after the commit and
            // before its confirmation still restores.
            Some(anchors) => self.store.commit_anchored(revision, &changes, &mut |next| {
                anchors.save(
                    scope,
                    AnchorSlots {
                        current,
                        next: Some(next),
                    },
                )
            }),
            None => self.store.commit(revision, &changes),
        };
        if let Err(error) = committed {
            self.uncertain = true;
            return Err(errors::store(error));
        }
        if let Err(error) = self.read_back(&records, &written) {
            self.uncertain = true;
            return Err(error);
        }
        if let Some(anchors) = &anchors {
            let confirmed = AnchorSlots {
                current: self.store.freshness(),
                next: None,
            };
            if let Err(error) = anchors.save(scope, confirmed) {
                self.uncertain = true;
                return Err(ApiError::storage_failed(format!(
                    "freshness anchor was not confirmed: {error}"
                )));
            }
        }
        self.committed = token.to_vec();
        Ok(())
    }

    /// The stored set is exactly `records`, and every record just written
    /// reads back byte for byte. Unchanged records were not written.
    fn read_back(&self, records: &SecurityRecords, written: &[Vec<u8>]) -> Result<(), ApiError> {
        let keys = self.store.keys(b"");
        if keys.len() != records.len() || keys.iter().any(|name| !records.contains_key(name)) {
            return Err(ApiError::storage_failed("record set did not read back"));
        }
        for name in written {
            let stored = self.store.get(name).map_err(errors::store)?;
            if stored.as_deref().map(Vec::as_slice)
                != records.get(name).map(|value| value.as_slice())
            {
                return Err(ApiError::storage_failed("record did not read back"));
            }
        }
        Ok(())
    }

    fn terminal(&self) -> Result<bool, ApiError> {
        let view = Logical::current(self.store.as_ref());
        Ok(view.get(RESET)?.is_some() || view.get(REMOVED)?.is_some())
    }
}

/// Unknown and newer runtime formats fail with `FormatNotSupported`.
fn stored_format(bytes: Option<&[u8]>) -> Result<u32, ApiError> {
    let bytes = bytes.ok_or_else(|| {
        ApiError::format_not_supported("record store has no runtime format record")
    })?;
    let found = u32::from_be_bytes(bytes.try_into().map_err(|_| {
        ApiError::format_not_supported("record store has an invalid runtime format record")
    })?);
    if found == 0 || found > RUNTIME_FORMAT {
        return Err(ApiError::format_not_supported(format!(
            "runtime record format {found} is newer than supported format {RUNTIME_FORMAT}"
        )));
    }
    Ok(found)
}

/// Upgrade `records` from format `from` with `migrations` (the migration
/// hook). Records at the current format are unchanged.
fn migrate(
    records: &mut SecurityRecords,
    from: u32,
    migrations: &[Migration],
) -> Result<bool, ApiError> {
    let pending = migrations.get(from as usize - 1..).ok_or_else(|| {
        ApiError::format_not_supported(format!("no migration from format {from}"))
    })?;
    for migration in pending {
        migration(records)?;
    }
    Ok(!pending.is_empty())
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
    records.insert(
        ACTIVITY.to_vec(),
        Zeroizing::new(encode_activity(activity)?),
    );
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

pub(crate) fn record_key(session: &Session) -> Result<arachne_security::StorageKey, ApiError> {
    session
        .storage
        .as_ref()
        .ok_or_else(storage_required)?
        .record_key()
}

pub(crate) fn storage_required() -> ApiError {
    ApiError::wrong_state("record storage required; attach storage to the session")
}

fn pending_records(
    session: &Session,
    pending: &arachne_security::PendingJoin,
) -> Result<SecurityRecords, ApiError> {
    let bytes = pending
        .seal(&record_key(session)?)
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
    let provider = &session
        .storage
        .as_ref()
        .ok_or_else(storage_required)?
        .provider;
    let endpoint = session.node.id();
    let config = session.storage.as_ref().ok_or_else(storage_required)?;
    if let Some(store) = provider.open(workspace).map_err(errors::store)? {
        let store = NativeStore::new(store, workspace, config, endpoint, Vec::new());
        // An empty store is one whose first save failed: nothing to keep.
        let empty = store.store.keys(b"").is_empty();
        if !empty && !store.terminal()? {
            return Err(ApiError::wrong_state(
                "record store already initialized; restore it",
            ));
        }
        return Ok(store);
    }
    Ok(NativeStore::new(
        provider.create(workspace).map_err(errors::store)?,
        workspace,
        config,
        endpoint,
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
            .seal(&record_key(session)?)
            .map_err(security(ErrorCode::StorageFailed))?;
        BTreeMap::from([(REMOVED.to_vec(), Zeroizing::new(bytes))])
    } else {
        return Err(ApiError::wrong_state("session has no candidate"));
    };
    if session.transition.staged.is_some() {
        records.extend(membership::fork::records(session, true)?);
    }
    session
        .records
        .as_mut()
        .ok_or_else(storage_required)?
        .commit(records, token)
}

/// Storage may hold a state that live state did not take: stop the session
/// until it is closed and restored.
pub(crate) fn mark_uncertain(session: &mut Session) {
    if let Some(store) = session.records.as_mut() {
        store.uncertain = true;
    }
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
        (
            ACTIVITY.to_vec(),
            Zeroizing::new(encode_activity(activity)?),
        ),
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
    with_session(handle, freshness).map_err(errors::text)
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
    let config = session
        .storage
        .as_ref()
        .ok_or_else(storage_required)?
        .clone();
    if config.requires_freshness && expected.is_none() && config.anchors.is_none() {
        return Err(ApiError::candidate_stale(
            "a freshness anchor is required to restore persistent storage",
        ));
    }
    let provider = &config.provider;
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
    // With monotonic anchor storage the anchor is required.
    if let Some(anchors) = &config.anchors {
        let slots = anchors
            .load(workspace)
            .map_err(errors::store)?
            .ok_or_else(|| {
                ApiError::candidate_stale(
                    "no saved freshness anchor for this workspace; restore refused",
                )
            })?;
        let found = store.freshness();
        if !slots.accepts(found) {
            return Err(ApiError::candidate_stale(
                "record store freshness anchor mismatch",
            ));
        }
        if slots.current != found {
            // The last commit landed; confirm its anchor now.
            anchors
                .save(
                    workspace,
                    AnchorSlots {
                        current: found,
                        next: None,
                    },
                )
                .map_err(errors::store)?;
        }
    }
    let format_record = store
        .get(FORMAT)
        .map_err(errors::store)?
        .map(|bytes| bytes.to_vec());
    let raw_token = store.get(TOKEN).map_err(errors::store)?;
    let legacy = format_record.is_none()
        && raw_token
            .as_deref()
            .is_some_and(|token| token.first() != Some(&WHOLE));
    let corrupt = |detail: &str| ApiError::storage_corrupt(detail);
    let view = if legacy {
        Logical::legacy(store.as_ref())
    } else {
        Logical::current(store.as_ref())
    };
    let committed = view
        .get(TOKEN)?
        .ok_or_else(|| corrupt("missing native commit token"))?
        .to_vec();
    if committed.len() != 37 || !committed.starts_with(b"DFRC\x01") {
        return Err(corrupt("invalid native commit token"));
    }
    if view.get(RESET)?.is_some() {
        return Err(ApiError::wrong_state("native record store was reset"));
    }
    let format = if legacy {
        0
    } else {
        stored_format(view.get(FORMAT)?.as_deref().map(|bytes| bytes.as_slice()))?
    };
    let endpoint = session.node.id();
    if !legacy
        && view.get(ENDPOINT)?.as_deref().map(|bytes| bytes.as_slice()) != Some(endpoint.as_slice())
    {
        return Err(ApiError::wrong_state(
            "the stored workspace belongs to a different endpoint key; restore it with that endpoint identity",
        ));
    }
    drop(view);
    let mut store = NativeStore::new(store, workspace, &config, endpoint, committed);
    if format != 0 && format != RUNTIME_FORMAT {
        // The migration hook: upgrade every record, then save them as one
        // commit before any is used.
        let view = Logical::current(store.store.as_ref());
        let mut records: SecurityRecords = view
            .keys(b"")
            .into_iter()
            .map(|name| {
                let value = view.get(&name)?;
                Ok((name, value.ok_or_else(|| corrupt("missing record"))?))
            })
            .collect::<Result<_, ApiError>>()?;
        drop(view);
        if migrate(&mut records, format, MIGRATIONS)? {
            let token = store.committed.clone();
            store.commit(records, &token)?;
        }
    }
    let get = |name: &[u8]| {
        Logical {
            store: store.store.as_ref(),
            legacy,
        }
        .get(name)
    };
    let keys = if legacy {
        Logical::legacy(store.store.as_ref()).keys(b"")
    } else {
        Logical::current(store.store.as_ref()).keys(b"")
    };
    if let Some(bytes) = get(PENDING)? {
        if keys.iter().any(|name| {
            ![PENDING, TOKEN, ENDPOINT, FORMAT, JOIN_LIFECYCLE, ACTIVITY].contains(&name.as_slice())
        }) {
            return Err(corrupt("pending store contains other lifecycle state"));
        }
        let pending = arachne_security::PendingJoin::restore(
            &record_key(session)?,
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
        if legacy {
            let records = pending_records(
                session,
                session
                    .join
                    .pending
                    .as_ref()
                    .ok_or_else(errors::no_pending_join)?,
            )?;
            let token = store.committed.clone();
            store.commit(records, &token)?;
        }
        session.records = Some(store);
        return Ok(Restored::Pending(value));
    }
    if let Some(bytes) = get(REMOVED)? {
        if keys.len() != if legacy { 2 } else { 4 } {
            return Err(corrupt("removed store contains active state"));
        }
        let removed = arachne_security::RemovedMembership::restore(
            &record_key(session)?,
            session.node.id(),
            workspace,
            &bytes,
        )
        .map_err(security(ErrorCode::StorageCorrupt))?;
        if legacy {
            let records = BTreeMap::from([(REMOVED.to_vec(), Zeroizing::new(bytes.to_vec()))]);
            let token = store.committed.clone();
            store.commit(records, &token)?;
        }
        let mut value = Removed::of(&removed, store.store.freshness());
        value.workspace = workspace;
        session.ending = true;
        return Ok(Restored::Removed(RemovedDurably {
            removed: value,
            durable: true,
        }));
    }
    for name in &keys {
        if !name.starts_with(b"security/")
            && !name.starts_with(membership::fork::PREFIX)
            && ![TOKEN, ENDPOINT, FORMAT, INBOX, ACTIVITY].contains(&name.as_slice())
        {
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
    if !matches!(
        activity.phase,
        WorkspacePhase::Active | WorkspacePhase::Recovering
    ) {
        return Err(corrupt("active store has invalid workspace activity"));
    }
    let branch_records = keys
        .iter()
        .filter(|name| name.starts_with(membership::fork::PREFIX))
        .map(|name| {
            Ok((
                name.clone(),
                get(name)?.ok_or_else(|| corrupt("missing branch record"))?,
            ))
        })
        .collect::<Result<SecurityRecords, ApiError>>()?;
    membership::fork::restore(session, &branch_records, &owner)?;
    session.activity = activity;
    session.delivery.publisher = publisher;
    session.delivery.inbox = inbox;
    commit_workspace(session, owner);
    value.activity = session.activity.view();
    if legacy {
        let workspace = session
            .workspace
            .as_ref()
            .ok_or_else(|| ApiError::internal("restored workspace was not committed"))?;
        let records = active_records(
            workspace,
            session.delivery.publisher.as_ref(),
            session.delivery.inbox.as_ref(),
            &session.activity,
        )?;
        let token = store.committed.clone();
        store.commit(records, &token)?;
    }
    session.records = Some(store);
    Ok(Restored::Opened(value))
}

/// Test fixture: write `owner` (and its delivery state) into `provider` in
/// the runtime record layout, as if a session had created it. Tests use it
/// to build state outside the runtime and then restore it. Not an import
/// path: nothing on a session accepts state bytes.
#[doc(hidden)]
#[cfg(any(test, feature = "test-fixtures"))]
pub fn seed_workspace(
    provider: &dyn StorageProvider,
    owner: &Workspace,
    publisher: Option<&arachne_delivery::PublisherLog>,
    inbox: Option<&arachne_delivery::inbox::ObjectInbox>,
) -> Result<FreshnessAnchor, String> {
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
    store_records.insert(
        TOKEN.to_vec(),
        Zeroizing::new(candidate_token().map_err(errors::text)?),
    );
    store_records.insert(ENDPOINT.to_vec(), Zeroizing::new(owner.endpoint().to_vec()));
    store_records.insert(
        FORMAT.to_vec(),
        Zeroizing::new(RUNTIME_FORMAT.to_be_bytes().to_vec()),
    );
    let store_records = expand(&store_records).map_err(errors::text)?;
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
    store
        .commit(revision, &changes)
        .map_err(|e| e.to_string())?;
    Ok(store.freshness())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_format_two(records: &mut SecurityRecords) -> Result<(), ApiError> {
        records.insert(b"runtime/added".to_vec(), Zeroizing::new(vec![2]));
        Ok(())
    }

    /// A3g: a record larger than the store's record limit (the MLS tree of a
    /// large roster) is saved as parts and reads back whole.
    #[test]
    fn a_record_above_the_store_limit_is_saved_in_parts() {
        let provider = MemoryProvider::default();
        let config = StorageConfig::memory(&provider);
        let scope = [5; 32];
        let mut store = NativeStore::new(
            provider.create(scope).unwrap(),
            scope,
            &config,
            [6; 32],
            Vec::new(),
        );
        let large: Vec<u8> = (0..3 * arachne_store::MAX_RECORD_BYTES + 7)
            .map(|index| index as u8)
            .collect();
        let records = SecurityRecords::from([
            (b"security/large".to_vec(), Zeroizing::new(large.clone())),
            (b"security/small".to_vec(), Zeroizing::new(vec![1, 2, 3])),
        ]);
        store.commit(records, &candidate_token().unwrap()).unwrap();
        let view = Logical::current(store.store.as_ref());
        assert_eq!(
            view.get(b"security/large").unwrap().unwrap().as_slice(),
            large
        );
        assert_eq!(
            view.get(b"security/small").unwrap().unwrap().as_slice(),
            [1, 2, 3]
        );
        assert_eq!(
            view.keys(b"security/"),
            vec![b"security/large".to_vec(), b"security/small".to_vec()]
        );
        // Shrinking it deletes the parts it no longer needs.
        let records =
            SecurityRecords::from([(b"security/large".to_vec(), Zeroizing::new(vec![9]))]);
        store.commit(records, &candidate_token().unwrap()).unwrap();
        assert_eq!(store.store.keys(b"security/").len(), 1);
        assert_eq!(view_get(&store, b"security/large"), vec![9]);
    }

    fn view_get(store: &NativeStore, name: &[u8]) -> Vec<u8> {
        Logical::current(store.store.as_ref())
            .get(name)
            .unwrap()
            .unwrap()
            .to_vec()
    }

    #[test]
    fn the_migration_hook_runs_each_step_from_the_stored_format() {
        let mut records = SecurityRecords::new();
        // Current format: nothing to do.
        assert!(!migrate(&mut records, 1, MIGRATIONS).unwrap());
        // A later build with one step (format 1 to 2) upgrades format 1 records.
        assert!(migrate(&mut records, 1, &[to_format_two]).unwrap());
        assert_eq!(records[b"runtime/added".as_slice()].as_slice(), [2]);
        assert!(!migrate(&mut records, 2, &[to_format_two]).unwrap());
        assert_eq!(
            stored_format(None).unwrap_err().code(),
            ErrorCode::FormatNotSupported
        );
        assert_eq!(
            stored_format(Some(&2u32.to_be_bytes())).unwrap_err().code(),
            ErrorCode::FormatNotSupported
        );
        assert_eq!(stored_format(Some(&1u32.to_be_bytes())).unwrap(), 1);
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl StorageConfig {
    /// Open native SQLite storage from a host-private directory and a separate
    /// 32-byte storage root. The root is validated before a provider is made.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn open_sqlite(directory: String, root: Vec<u8>) -> Result<Arc<Self>, ApiError> {
        let root: [u8; 32] = root
            .try_into()
            .map_err(|_| ApiError::invalid_input("storage_root", "must contain 32 bytes"))?;
        if directory.is_empty() {
            return Err(ApiError::invalid_input("directory", "must not be empty"));
        }
        Ok(Arc::new(Self::sqlite(Path::new(&directory), root)))
    }
}

#[cfg(feature = "uniffi")]
uniffi::custom_type!(FreshnessAnchor, Vec<u8>, {
    remote,
    lower: |anchor| anchor.to_bytes().to_vec(),
    try_lift: |bytes| Ok(FreshnessAnchor::from_bytes(&bytes)
        .map_err(|_| ApiError::invalid_input("anchor", "must contain 40 bytes"))?),
});
